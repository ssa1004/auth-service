package com.example.auth.e2e

import com.example.auth.application.port.out.RefreshTokenRepository
import com.example.auth.application.port.out.TenantRepository
import com.example.auth.domain.tenant.Tenant
import com.example.auth.domain.token.TokenHasher
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Base64
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired

/**
 * RFC 7662 Token Introspection 의 표준 응답 형식 + revoke 즉시 반영 검증.
 *
 * 시나리오:
 * 1. 회원가입 + 로그인으로 access / refresh 발급
 * 2. POST oauth2 introspect 로 access token 조회 → active=true + 표준 claim
 * 3. POST oauth2 introspect 로 refresh token 조회 → active=true
 * 4. refresh 를 직접 revoke (admin 모드 simulation) 후 다시 introspect → active=false
 * 5. 호출에 client_secret_basic 인증이 없으면 401
 * 6. 외부에서 만든 가짜 token → active=false (정보 누설 X)
 */
class IntrospectionE2eTest : AbstractE2eTest() {

    @Autowired
    lateinit var tenantRepository: TenantRepository

    @Autowired
    lateinit var refreshTokenRepository: RefreshTokenRepository

    private val http: HttpClient = HttpClient.newHttpClient()

    @BeforeEach
    fun seedTenant() {
        if (tenantRepository.findBySlug("acme").isEmpty) {
            tenantRepository.save(Tenant.create("acme", "ACME", Instant.now()))
        }
    }

    @Test
    fun `introspect 는 RFC 7662 표준 응답을 반환하고 revoke 즉시 반영`() {
        // 1) register + login
        val email = "introspect+${System.nanoTime()}@example.com"
        post(
            "/api/v1/auth/register",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234"}""",
        )

        val login = post(
            "/api/v1/auth/login",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234","deviceLabel":"e2e-introspect"}""",
        )
        assertThat(login.statusCode()).isEqualTo(200)
        val access = json(login.body(), "accessToken")!!
        val refresh = json(login.body(), "refreshToken")!!

        // 2) access token introspect
        val accessRes = introspect("token=${urlEncode(access)}&token_type_hint=access_token")
        assertThat(accessRes.statusCode()).isEqualTo(200)
        val accessBody = accessRes.body()
        // RFC 7662 §2.2 표준 필드
        assertThat(accessBody).contains("\"active\":true")
        assertThat(accessBody).contains("\"token_type\":\"Bearer\"")
        assertThat(accessBody).contains("\"sub\":")
        assertThat(accessBody).contains("\"tnt\":")
        assertThat(accessBody).contains("\"iss\":")
        assertThat(accessBody).contains("\"exp\":")
        assertThat(accessBody).contains("\"iat\":")
        assertThat(accessBody).contains("\"jti\":")

        // 3) refresh token introspect
        val refreshRes = introspect("token=${urlEncode(refresh)}&token_type_hint=refresh_token")
        assertThat(refreshRes.statusCode()).isEqualTo(200)
        assertThat(refreshRes.body()).contains("\"active\":true")

        // 4) refresh 를 admin revoke 한 것처럼 직접 status 변경 → 다시 introspect
        val rt = refreshTokenRepository.findByTokenHashReadOnly(TokenHasher.sha256(refresh)).orElseThrow()
        refreshTokenRepository.save(rt.markRevokedByAdmin(Instant.now()))

        val afterRevoke = introspect("token=${urlEncode(refresh)}&token_type_hint=refresh_token")
        assertThat(afterRevoke.statusCode()).isEqualTo(200)
        assertThat(afterRevoke.body()).contains("\"active\":false")
        // 정보 누설 방지 — sub / tnt 같은 필드는 응답에 없어야 함.
        assertThat(afterRevoke.body()).doesNotContain("\"sub\":")
        assertThat(afterRevoke.body()).doesNotContain("\"tnt\":")

        // 5) client 인증 없이 호출 → 401
        val unauth = http.send(
            HttpRequest.newBuilder(URI.create("${baseUrl()}/oauth2/introspect"))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("token=${urlEncode(access)}"))
                .build(),
            HttpResponse.BodyHandlers.ofString(),
        )
        assertThat(unauth.statusCode()).isEqualTo(401)

        // 6) 가짜 token 도 active=false (정보 누설 차단)
        val fake = introspect("token=${urlEncode("not-a-real-token-at-all")}")
        assertThat(fake.statusCode()).isEqualTo(200)
        assertThat(fake.body()).contains("\"active\":false")
    }

    private fun introspect(formBody: String): HttpResponse<String> {
        val basic = Base64.getEncoder()
            .encodeToString("$CLIENT_ID:$CLIENT_SECRET".toByteArray())
        return http.send(
            HttpRequest.newBuilder(URI.create("${baseUrl()}/oauth2/introspect"))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic $basic")
                .POST(HttpRequest.BodyPublishers.ofString(formBody))
                .build(),
            HttpResponse.BodyHandlers.ofString(),
        )
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

    companion object {
        private const val CLIENT_ID = "internal-service"
        private const val CLIENT_SECRET = "internal-service-secret-change-me"

        private fun json(body: String, key: String): String? {
            val prefix = "\"$key\":\""
            val start = body.indexOf(prefix)
            if (start < 0) return null
            val from = start + prefix.length
            val end = body.indexOf("\"", from)
            return if (end < 0) null else body.substring(from, end)
        }

        private fun urlEncode(s: String): String =
            URLEncoder.encode(s, StandardCharsets.UTF_8)
    }
}
