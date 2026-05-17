package com.example.auth.bootstrap.health

import com.example.auth.adapter.out.security.JwkSourceProvider
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import java.util.Collections
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.springframework.boot.actuate.health.Health
import org.springframework.boot.actuate.health.HealthContributor
import org.springframework.boot.actuate.health.HealthContributorRegistry
import org.springframework.boot.actuate.health.HealthIndicator
import org.springframework.boot.actuate.health.NamedContributor
import org.springframework.boot.availability.ApplicationAvailability
import org.springframework.boot.availability.AvailabilityChangeEvent
import org.springframework.boot.availability.AvailabilityState
import org.springframework.boot.availability.LivenessState
import org.springframework.boot.availability.ReadinessState
import org.springframework.context.ApplicationListener
import org.springframework.context.support.GenericApplicationContext

/**
 * ApplicationReadinessCoordinator (ADR-0010) 단위 테스트.
 *
 * 실 Redis / Postgres 가 없는 환경 — HealthContributorRegistry 만 fake 로 주입.
 */
class ApplicationReadinessCoordinatorTest {

    private lateinit var context: GenericApplicationContext
    private lateinit var availability: RecordingAvailability
    private lateinit var healthRegistry: FakeHealthRegistry

    @BeforeEach
    fun setUp() {
        context = GenericApplicationContext()
        context.refresh()
        availability = RecordingAvailability()
        context.addApplicationListener(availability)
        healthRegistry = FakeHealthRegistry()
    }

    @Test
    fun `JWK 초기 키 없으면 onReady 가 예외를 던진다`() {
        val emptyProvider = mock(JwkSourceProvider::class.java)
        `when`(emptyProvider.jwkSet()).thenReturn(JWKSet(Collections.emptyList()))

        val coordinator = ApplicationReadinessCoordinator(
            availability, context, healthRegistry, emptyProvider,
        )

        assertThatThrownBy { coordinator.onReady() }
            .isInstanceOf(IllegalStateException::class.java)
            .hasMessageContaining("JWK 초기 키 미생성")
    }

    @Test
    fun `DB 와 Redis 모두 UP 이면 readiness 는 ACCEPTING 으로 유지`() {
        healthRegistry.put("db") { Health.up().build() }
        healthRegistry.put("redis") { Health.up().build() }

        val coordinator = newCoordinator()
        coordinator.onReady()

        assertThat(availability.readinessState).isEqualTo(ReadinessState.ACCEPTING_TRAFFIC)
        coordinator.recheckExternalDependencies()
        assertThat(availability.readinessState).isEqualTo(ReadinessState.ACCEPTING_TRAFFIC)
    }

    @Test
    fun `DB 가 연속 3회 DOWN 이면 REFUSING 으로 전환`() {
        healthRegistry.put("db") { Health.down().build() }
        healthRegistry.put("redis") { Health.up().build() }

        val coordinator = newCoordinator()
        coordinator.onReady()
        assertThat(availability.readinessState).isEqualTo(ReadinessState.ACCEPTING_TRAFFIC)

        coordinator.recheckExternalDependencies()
        coordinator.recheckExternalDependencies()
        // 2회까지는 ACCEPTING — 외부 의존이 잠깐 흔들렸을 수도 있어서 여유.
        assertThat(availability.readinessState).isEqualTo(ReadinessState.ACCEPTING_TRAFFIC)

        coordinator.recheckExternalDependencies()
        // 3회 연속 → REFUSING.
        assertThat(availability.readinessState).isEqualTo(ReadinessState.REFUSING_TRAFFIC)
    }

    @Test
    fun `Redis 가 연속 3회 DOWN 이어도 REFUSING`() {
        healthRegistry.put("db") { Health.up().build() }
        healthRegistry.put("redis") { Health.down().build() }

        val coordinator = newCoordinator()
        coordinator.onReady()

        coordinator.recheckExternalDependencies()
        coordinator.recheckExternalDependencies()
        coordinator.recheckExternalDependencies()
        assertThat(availability.readinessState).isEqualTo(ReadinessState.REFUSING_TRAFFIC)
    }

    @Test
    fun `liveness 는 external 의존 DOWN 과 무관하게 CORRECT 유지`() {
        // liveness=BROKEN 으로 가면 K8s 가 컨테이너를 재시작합니다. DB 일시 장애로 살아있는
        // pod 까지 죽여 장애가 더 커지는 것을 막기 위해 liveness 는 외부 의존을 보지 않습니다.
        healthRegistry.put("db") { Health.down().build() }
        healthRegistry.put("redis") { Health.down().build() }

        val coordinator = newCoordinator()
        coordinator.onReady()
        coordinator.recheckExternalDependencies()
        coordinator.recheckExternalDependencies()
        coordinator.recheckExternalDependencies()

        assertThat(availability.livenessState).isEqualTo(LivenessState.CORRECT)
    }

    private fun newCoordinator(): ApplicationReadinessCoordinator =
        ApplicationReadinessCoordinator(availability, context, healthRegistry, providerWithKey())

    /** 이름 → HealthIndicator 의 단순 in-memory registry. */
    private class FakeHealthRegistry : HealthContributorRegistry {

        private val contributors: MutableMap<String, HealthContributor> = ConcurrentHashMap()

        fun put(name: String, indicator: HealthIndicator) {
            contributors[name] = indicator
        }

        override fun getContributor(name: String): HealthContributor? = contributors[name]

        override fun registerContributor(name: String, contributor: HealthContributor) {
            contributors[name] = contributor
        }

        override fun unregisterContributor(name: String): HealthContributor? =
            contributors.remove(name)

        override fun iterator(): MutableIterator<NamedContributor<HealthContributor>> =
            contributors.entries
                .map { (k, v) -> NamedContributor.of(k, v) }
                .toMutableList()
                .iterator()
    }

    /**
     * AvailabilityChangeEvent 를 listener 로 받아 마지막 상태를 기록하는 fake.
     */
    private class RecordingAvailability :
        ApplicationAvailability,
        ApplicationListener<AvailabilityChangeEvent<*>> {

        private val last: MutableMap<Class<*>, AvailabilityState> = ConcurrentHashMap()

        override fun onApplicationEvent(event: AvailabilityChangeEvent<*>) {
            last[event.state.javaClass] = event.state
        }

        override fun getLivenessState(): LivenessState =
            (last.getOrDefault(LivenessState::class.java, LivenessState.CORRECT)) as LivenessState

        override fun getReadinessState(): ReadinessState =
            (last.getOrDefault(
                ReadinessState::class.java,
                ReadinessState.ACCEPTING_TRAFFIC,
            )) as ReadinessState

        @Suppress("UNCHECKED_CAST")
        override fun <S : AvailabilityState> getState(stateType: Class<S>): S? =
            last[stateType] as S?

        @Suppress("UNCHECKED_CAST")
        override fun <S : AvailabilityState> getState(stateType: Class<S>, defaultState: S): S =
            (last[stateType] as S?) ?: defaultState

        override fun <S : AvailabilityState> getLastChangeEvent(
            stateType: Class<S>,
        ): AvailabilityChangeEvent<S>? = null
    }

    companion object {
        private fun providerWithKey(): JwkSourceProvider {
            val key: JWK = RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .keyUse(KeyUse.SIGNATURE)
                .generate()
            return JwkSourceProvider(key)
        }
    }
}
