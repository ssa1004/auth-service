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

/**
 * 실 Postgres + Redis + 전체 부팅된 Spring + REST 호출.
 *
 * 시나리오:
 * 1. POST /api/v1/auth/register 로 신규 사용자 가입
 * 2. POST /api/v1/auth/login 으로 access + refresh 발급
 * 3. POST /api/v1/auth/refresh 로 회전
 * 4. 회전된 token 을 다시 보내 reuse detection → 401
 */
class RegisterAndLoginE2eTest : AbstractE2eTest() {

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
    fun `회원가입 로그인 refresh 회전 그리고 reuse detection 까지`() {
        // 1) register
        val reg = post(
            "/api/v1/auth/register",
            """{"tenantSlug":"acme","email":"e2e+${System.nanoTime()}@example.com","password":"longenoughpw1234"}""",
        )
        assertThat(reg.statusCode()).isEqualTo(201)

        // 단순화: 같은 email 로 즉시 로그인.
        val userEmail = "e2e+login@example.com"
        post(
            "/api/v1/auth/register",
            """{"tenantSlug":"acme","email":"$userEmail","password":"longenoughpw1234"}""",
        )

        // 2) login
        val login = post(
            "/api/v1/auth/login",
            """{"tenantSlug":"acme","email":"$userEmail","password":"longenoughpw1234","deviceLabel":"e2e"}""",
        )
        assertThat(login.statusCode()).isEqualTo(200)
        val access = json(login.body(), "accessToken")!!
        val refresh = json(login.body(), "refreshToken")!!
        assertThat(access).startsWith("ey")
        assertThat(refresh).isNotBlank

        // 3) refresh 정상 회전
        val rotated = post(
            "/api/v1/auth/refresh",
            """{"refreshToken":"$refresh"}""",
        )
        assertThat(rotated.statusCode()).isEqualTo(200)
        val newRefresh = json(rotated.body(), "refreshToken")
        assertThat(newRefresh).isNotEqualTo(refresh)

        // 4) 회전된 refresh 를 다시 사용 → reuse detection.
        //    grace 윈도우 (5초, ADR-0015) 우회를 위해 다른 IP 로 가정하는 X-Forwarded-For 사용.
        val reuse = postWithIp(
            "/api/v1/auth/refresh",
            """{"refreshToken":"$refresh"}""",
            "9.9.9.9",
        )
        assertThat(reuse.statusCode()).isEqualTo(401)
        assertThat(reuse.body()).contains("refresh_reuse_detected")

        // 5) 새 refresh 도 사용 불가 (모든 세션 강제 revoke 됨)
        val afterReuse = post(
            "/api/v1/auth/refresh",
            """{"refreshToken":"$newRefresh"}""",
        )
        assertThat(afterReuse.statusCode()).isEqualTo(401)
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

    /**
     * X-Forwarded-For 로 다른 client IP 를 가정 — grace 윈도우 회피 (ADR-0015) 검증용.
     *
     * e2e 의 호출자는 loopback (127.0.0.1) 이고 application.yml 에서 loopback 을
     * trusted-proxies 로 등록했으므로 헤더가 적용됩니다. 운영에서는 LB 의 사설 CIDR 만
     * trusted 로 설정 — 외부 직접 호출자의 X-Forwarded-For 는 위조로 간주되어 무시됩니다.
     */
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
        // 매우 단순한 JSON 파서 — 따옴표로 감싼 값만 추출. e2e 검증 용도로만.
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
