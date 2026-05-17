package com.example.auth.e2e

import com.example.auth.application.port.out.TenantRepository
import com.example.auth.domain.tenant.Tenant
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
import org.springframework.test.context.TestPropertySource

/**
 * X-Forwarded-For 위조 차단의 종단간 검증.
 *
 * [RegisterAndLoginE2eTest] 는 loopback 을 trusted-proxy 로 등록한 *기본* 환경에서
 * 헤더가 적용되는 흐름을 검증합니다. 본 클래스는 그 반대 — trusted-proxies 를 빈 목록으로
 * 덮어써 *외부 직접 호출자 시뮬레이션* 환경을 만든 뒤, X-Forwarded-For 위조 시도가 무시되어
 * 같은 IP 처리 (= refresh reuse grace 진입) 되는지 확인합니다.
 *
 * 회귀 락다운 — 운영 default 인 빈 trusted-proxies 환경에서 위조가 통하지 않음을 보장.
 */
@TestPropertySource(properties = ["auth.trusted-proxies="])
class TrustedProxyE2eTest : AbstractE2eTest() {

    @Autowired
    lateinit var tenantRepository: TenantRepository

    private val http: HttpClient = HttpClient.newHttpClient()

    @BeforeEach
    fun seedTenant() {
        if (tenantRepository.findBySlug("acme").isEmpty) {
            tenantRepository.save(Tenant.create("acme", "ACME", Instant.now()))
        }
    }

    @Test
    fun `trusted proxy 가 비어있으면 위조된 X-Forwarded-For 는 무시되어 grace 가 적용됨`() {
        // 1) register + login → refresh / access 발급
        val email = "trusted+${System.nanoTime()}@example.com"
        post(
            "/api/v1/auth/register",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234"}""",
        )
        val login = post(
            "/api/v1/auth/login",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234","deviceLabel":"trust"}""",
        )
        assertThat(login.statusCode()).isEqualTo(200)
        val refresh = json(login.body(), "refreshToken")!!

        // 2) 정상 회전 — 같은 loopback IP 로
        val rotated = post(
            "/api/v1/auth/refresh",
            """{"refreshToken":"$refresh"}""",
        )
        assertThat(rotated.statusCode()).isEqualTo(200)
        val newRefresh = json(rotated.body(), "refreshToken")!!

        // 3) 회전된 token 을 X-Forwarded-For 위조해서 다시 보냄.
        //    trusted-proxies 가 비어있으므로 위조 헤더는 무시 → 같은 IP (= loopback) 처리
        //    → grace window 안 + sameNetwork=true → 401 (RefreshReuseDetected 가 아닌 InvalidCredentials).
        val reuse = postWithIp(
            "/api/v1/auth/refresh",
            """{"refreshToken":"$refresh"}""",
            "9.9.9.9",
        )
        assertThat(reuse.statusCode()).isEqualTo(401)
        // grace 처리는 invalid_credentials, 진짜 reuse 는 refresh_reuse_detected.
        // 위조가 *통했다면* refresh_reuse_detected 가 나와야 하지만, 차단됐으니 그렇지 않음.
        assertThat(reuse.body()).doesNotContain("refresh_reuse_detected")

        // 4) 새 refresh 는 여전히 살아있어야 함 (grace 처리 → 일괄 revoke 트리거 안 됨).
        val stillAlive = post(
            "/api/v1/auth/refresh",
            """{"refreshToken":"$newRefresh"}""",
        )
        assertThat(stillAlive.statusCode()).isEqualTo(200)
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

    private fun postWithIp(path: String, body: String, forwardedIp: String): HttpResponse<String> =
        http.send(
            HttpRequest.newBuilder(URI.create("${baseUrl()}$path"))
                .timeout(Duration.ofSeconds(60))
                .header("Content-Type", "application/json")
                .header("X-Forwarded-For", forwardedIp)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(),
            HttpResponse.BodyHandlers.ofString(),
        )

    companion object {
        private fun json(body: String, key: String): String? {
            val prefix = "\"$key\":\""
            val start = body.indexOf(prefix)
            if (start < 0) return null
            val from = start + prefix.length
            val end = body.indexOf("\"", from)
            return if (end < 0) null else body.substring(from, end)
        }
    }
}
