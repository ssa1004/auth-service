package com.example.auth.e2e

import com.example.auth.adapter.out.security.JwkSourceProvider
import com.example.auth.application.port.out.TenantRepository
import com.example.auth.bootstrap.jwk.JwkRotationScheduler
import com.example.auth.domain.tenant.Tenant
import com.fasterxml.jackson.databind.ObjectMapper
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.jwt.JwtDecoder

/**
 * JWK rotation 의 실 동작을 ADR-0003 의 시나리오대로 검증.
 *
 * 본 테스트가 보장하는 invariant:
 * 1. 부팅 직후 JWKS endpoint 는 current 1개 키를 노출 (또는 previous 가 디스크에 살아있다면 2개).
 * 2. 회전 1회 후 — JWKS 가 current + previous 두 키를 노출. 회전 *전* 발급된 access JWT
 *    는 *previous* 로 검증 통과 — grace period 의 핵심 보장.
 * 3. 회전 *후* 발급된 새 access JWT 는 *current* 로 검증 통과.
 * 4. 두 token 이 서로 다른 kid 로 서명되어 있음 — JWT header.kid 가 다른지 확인.
 *
 * JwkRotationScheduler 는 운영에서 cron 24h 주기로 호출되지만, 테스트는 직접 메서드를
 * 호출하여 회전 사이클을 시뮬레이션합니다 — production 코드 수정 없음.
 */
class JwkRotationE2eTest : AbstractE2eTest() {

    @Autowired
    lateinit var rotationScheduler: JwkRotationScheduler

    @Autowired
    lateinit var jwkSourceProvider: JwkSourceProvider

    @Autowired
    lateinit var jwtDecoder: JwtDecoder

    @Autowired
    lateinit var tenantRepository: TenantRepository

    private val http: HttpClient = HttpClient.newHttpClient()
    private val om = ObjectMapper()

    @BeforeEach
    fun seedTenant() {
        if (tenantRepository.findBySlug("acme").isEmpty) {
            tenantRepository.save(Tenant.create("acme", "ACME", Instant.now()))
        }
    }

    @Test
    fun `회전 전 발급된 access 토큰은 회전 후에도 grace period 동안 검증 통과`() {
        // 1) 회전 전 — JWKS 의 현재 kid 기록.
        val kidsBeforeRotation = jwksKids()
        assertThat(kidsBeforeRotation).`as`("부팅 후 JWKS 에 최소 1개 키").isNotEmpty
        val currentKidBefore = jwkSourceProvider.current().keyID

        // 2) 사용자 로그인 → access JWT 발급. 이 token 은 회전 *전* 키로 서명됨.
        val accessBefore = loginAndGetAccessToken("rotate-before+${System.nanoTime()}@example.com")
        val parsedBefore = jwtDecoder.decode(accessBefore)
        val kidBeforeOnToken = parsedBefore.headers["kid"].toString()
        assertThat(kidBeforeOnToken).isEqualTo(currentKidBefore)

        // 3) 회전 1회 — production scheduler 의 메서드를 그대로 호출.
        rotationScheduler.rotate()

        // 4) JWKS 가 current + previous 두 개를 노출. 회전 전 kid 는 previous 로 보존되어야 함.
        val kidsAfter = jwksKids()
        assertThat(kidsAfter as Iterable<String>)
            .`as`("회전 후 JWKS 에 새 + 직전 kid 두 개")
            .hasSize(2)
            .contains(kidBeforeOnToken, jwkSourceProvider.current().keyID)
        assertThat(jwkSourceProvider.current().keyID)
            .`as`("회전 후 current 는 새 kid")
            .isNotEqualTo(kidBeforeOnToken)

        // 5) 회전 *전* 발급된 access JWT 가 여전히 검증 통과 — grace period 의 핵심 보장.
        val reparsed = jwtDecoder.decode(accessBefore)
        assertThat(reparsed.subject).isEqualTo(parsedBefore.subject)

        // 6) 회전 *후* 발급한 access JWT 도 검증 통과 + 새 kid 로 서명.
        val accessAfter = loginAndGetAccessToken("rotate-after+${System.nanoTime()}@example.com")
        val parsedAfter = jwtDecoder.decode(accessAfter)
        val kidAfter = parsedAfter.headers["kid"].toString()
        assertThat(kidAfter)
            .`as`("회전 후 새 token 은 새 kid 로 서명")
            .isEqualTo(jwkSourceProvider.current().keyID)
            .isNotEqualTo(kidBeforeOnToken)
    }

    @Test
    fun `두 번 회전 후에는 원래 키가 JWKS 에서 사라짐`() {
        val firstKid = jwkSourceProvider.current().keyID

        rotationScheduler.rotate()
        val secondKid = jwkSourceProvider.current().keyID
        assertThat(secondKid).isNotEqualTo(firstKid)

        rotationScheduler.rotate()
        val thirdKid = jwkSourceProvider.current().keyID
        assertThat(thirdKid).isNotEqualTo(secondKid).isNotEqualTo(firstKid)

        // JWKS 는 third (current) + second (previous) 두 개만. first 는 폐기.
        val kids = jwksKids()
        assertThat(kids as Iterable<String>)
            .`as`("두 번 회전 후 JWKS 는 새 + 직전 두 개만")
            .hasSize(2)
            .contains(thirdKid, secondKid)
            .doesNotContain(firstKid)
    }

    private fun loginAndGetAccessToken(email: String): String {
        post(
            "/api/v1/auth/register",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234"}""",
        )
        val login = post(
            "/api/v1/auth/login",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234","deviceLabel":"jwk-rotation-e2e"}""",
        )
        assertThat(login.statusCode()).isEqualTo(200)
        val body = om.readTree(login.body())
        val access = body.path("accessToken").asText()
        assertThat(access).`as`("login 응답에 accessToken").isNotBlank
        return access
    }

    private fun jwksKids(): MutableSet<String> {
        val res = http.send(
            HttpRequest.newBuilder(URI.create("${baseUrl()}/oauth2/jwks")).GET().build(),
            HttpResponse.BodyHandlers.ofString(),
        )
        assertThat(res.statusCode()).isEqualTo(200)
        val keys = om.readTree(res.body()).path("keys")
        val kids: MutableSet<String> = HashSet()
        for (k in keys) kids.add(k.path("kid").asText())
        return kids
    }

    private fun post(path: String, body: String): HttpResponse<String> =
        http.send(
            HttpRequest.newBuilder(URI.create("${baseUrl()}$path"))
                .timeout(Duration.ofSeconds(60))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(),
            HttpResponse.BodyHandlers.ofString(),
        )
}
