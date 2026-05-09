package com.example.auth.bootstrap.health;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.auth.adapter.out.security.JwkSourceProvider;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthContributor;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.NamedContributor;
import org.springframework.boot.availability.ApplicationAvailability;
import org.springframework.boot.availability.AvailabilityChangeEvent;
import org.springframework.boot.availability.AvailabilityState;
import org.springframework.boot.availability.LivenessState;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.context.ApplicationListener;
import org.springframework.context.support.GenericApplicationContext;

/**
 * ApplicationReadinessCoordinator (ADR-0010) 단위 테스트.
 *
 * <p>실 Redis / Postgres 가 없는 환경 — HealthContributorRegistry 만 fake 로 주입.
 */
class ApplicationReadinessCoordinatorTest {

    private GenericApplicationContext context;
    private RecordingAvailability availability;
    private FakeHealthRegistry healthRegistry;

    @BeforeEach
    void setUp() {
        context = new GenericApplicationContext();
        context.refresh();
        availability = new RecordingAvailability();
        context.addApplicationListener(availability);
        healthRegistry = new FakeHealthRegistry();
    }

    @Test
    void JWK_초기_키_없으면_onReady_가_예외를_던진다() {
        JwkSourceProvider emptyProvider = mock(JwkSourceProvider.class);
        when(emptyProvider.jwkSet()).thenReturn(new JWKSet(Collections.emptyList()));

        ApplicationReadinessCoordinator coordinator = new ApplicationReadinessCoordinator(
                availability, context, healthRegistry, emptyProvider);

        assertThatThrownBy(coordinator::onReady)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JWK 초기 키 미생성");
    }

    @Test
    void DB_와_Redis_모두_UP_이면_readiness_는_ACCEPTING_으로_유지() throws Exception {
        healthRegistry.put("db", () -> Health.up().build());
        healthRegistry.put("redis", () -> Health.up().build());

        ApplicationReadinessCoordinator coordinator = newCoordinator();
        coordinator.onReady();

        assertThat(availability.getReadinessState()).isEqualTo(ReadinessState.ACCEPTING_TRAFFIC);
        coordinator.recheckExternalDependencies();
        assertThat(availability.getReadinessState()).isEqualTo(ReadinessState.ACCEPTING_TRAFFIC);
    }

    @Test
    void DB_가_연속_3회_DOWN_이면_REFUSING_으로_전환() throws Exception {
        healthRegistry.put("db", () -> Health.down().build());
        healthRegistry.put("redis", () -> Health.up().build());

        ApplicationReadinessCoordinator coordinator = newCoordinator();
        coordinator.onReady();
        assertThat(availability.getReadinessState()).isEqualTo(ReadinessState.ACCEPTING_TRAFFIC);

        coordinator.recheckExternalDependencies();
        coordinator.recheckExternalDependencies();
        // 2회까지는 ACCEPTING — 외부 의존이 잠깐 흔들렸을 수도 있어서 여유.
        assertThat(availability.getReadinessState()).isEqualTo(ReadinessState.ACCEPTING_TRAFFIC);

        coordinator.recheckExternalDependencies();
        // 3회 연속 → REFUSING.
        assertThat(availability.getReadinessState()).isEqualTo(ReadinessState.REFUSING_TRAFFIC);
    }

    @Test
    void Redis_가_연속_3회_DOWN_이어도_REFUSING() throws Exception {
        healthRegistry.put("db", () -> Health.up().build());
        healthRegistry.put("redis", () -> Health.down().build());

        ApplicationReadinessCoordinator coordinator = newCoordinator();
        coordinator.onReady();

        coordinator.recheckExternalDependencies();
        coordinator.recheckExternalDependencies();
        coordinator.recheckExternalDependencies();
        assertThat(availability.getReadinessState()).isEqualTo(ReadinessState.REFUSING_TRAFFIC);
    }

    @Test
    void liveness_는_external_의존_DOWN_과_무관하게_CORRECT_유지() throws Exception {
        // liveness=BROKEN 으로 가면 K8s 가 컨테이너를 재시작 — DB 일시 장애로 살아있는
        // pod 죽이는 cascade 사고를 막기 위해 liveness 는 외부 의존 무시.
        healthRegistry.put("db", () -> Health.down().build());
        healthRegistry.put("redis", () -> Health.down().build());

        ApplicationReadinessCoordinator coordinator = newCoordinator();
        coordinator.onReady();
        coordinator.recheckExternalDependencies();
        coordinator.recheckExternalDependencies();
        coordinator.recheckExternalDependencies();

        assertThat(availability.getLivenessState()).isEqualTo(LivenessState.CORRECT);
    }

    private ApplicationReadinessCoordinator newCoordinator() throws Exception {
        return new ApplicationReadinessCoordinator(
                availability, context, healthRegistry, providerWithKey());
    }

    private static JwkSourceProvider providerWithKey() throws Exception {
        JWK key = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        return new JwkSourceProvider(key);
    }

    /** 이름 → HealthIndicator 의 단순 in-memory registry. */
    private static final class FakeHealthRegistry implements HealthContributorRegistry {

        private final Map<String, HealthContributor> contributors = new ConcurrentHashMap<>();

        void put(String name, HealthIndicator indicator) {
            contributors.put(name, indicator);
        }

        @Override
        public HealthContributor getContributor(String name) {
            return contributors.get(name);
        }

        @Override
        public void registerContributor(String name, HealthContributor contributor) {
            contributors.put(name, contributor);
        }

        @Override
        public HealthContributor unregisterContributor(String name) {
            return contributors.remove(name);
        }

        @Override
        public java.util.Iterator<NamedContributor<HealthContributor>> iterator() {
            return contributors.entrySet().stream()
                    .map(e -> NamedContributor.of(e.getKey(), e.getValue()))
                    .iterator();
        }
    }

    /**
     * AvailabilityChangeEvent 를 listener 로 받아 마지막 상태를 기록하는 fake.
     */
    private static final class RecordingAvailability
            implements ApplicationAvailability, ApplicationListener<AvailabilityChangeEvent<?>> {

        private final Map<Class<?>, AvailabilityState> last = new ConcurrentHashMap<>();

        @Override
        public void onApplicationEvent(AvailabilityChangeEvent<?> event) {
            last.put(event.getState().getClass(), event.getState());
        }

        @Override
        public LivenessState getLivenessState() {
            return (LivenessState) last.getOrDefault(LivenessState.class, LivenessState.CORRECT);
        }

        @Override
        public ReadinessState getReadinessState() {
            return (ReadinessState) last.getOrDefault(
                    ReadinessState.class, ReadinessState.ACCEPTING_TRAFFIC);
        }

        @Override
        @SuppressWarnings("unchecked")
        public <S extends AvailabilityState> S getState(Class<S> stateType) {
            return (S) last.get(stateType);
        }

        @Override
        @SuppressWarnings("unchecked")
        public <S extends AvailabilityState> S getState(Class<S> stateType, S defaultState) {
            S value = (S) last.get(stateType);
            return value != null ? value : defaultState;
        }

        @Override
        public <S extends AvailabilityState> AvailabilityChangeEvent<S> getLastChangeEvent(
                Class<S> stateType) {
            return null;
        }
    }
}
