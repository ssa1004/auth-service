package com.example.auth.e2e

import com.example.auth.application.port.out.RefreshTokenRepository
import com.example.auth.application.port.out.TenantRepository
import com.example.auth.domain.tenant.Tenant
import com.example.auth.domain.token.RefreshTokenStatus
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
 * RFC 7009 Token Revocation 의 admin scope 검증 + revoke 후 introspect=active:false 검증.
 *
 * 시나리오:
 * 1. register + login → refresh / access 발급
 * 2. internal-admin (token.revoke scope) 으로 POST oauth2 revoke 호출 → 200
 * 3. introspect 로 active=false 확인 (revoke 즉시 반영)
 * 4. internal-service (token.revoke 없음) 으로 revoke 시도 → 403
 * 5. 알 수 없는 token revoke → 200 (RFC 7009 §2.2 — 정보 누설 차단)
 * 6. revoke 된 refresh 의 status 가 REVOKED_BY_ADMIN 인지 직접 확인
 */
class RevokeTokenE2eTest : AbstractE2eTest() {

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
    fun `admin 은 refresh token 을 revoke 하고 introspect 가 즉시 inactive 로 바뀜`() {
        // 1) register + login
        val email = "revoke+${System.nanoTime()}@example.com"
        post(
            "/api/v1/auth/register",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234"}""",
        )
        val login = post(
            "/api/v1/auth/login",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234","deviceLabel":"e2e-revoke"}""",
        )
        assertThat(login.statusCode()).isEqualTo(200)
        val refresh = json(login.body(), "refreshToken")!!

        // 2) internal-admin 으로 refresh revoke → 200
        val revoke = revokeAs(
            ADMIN_CLIENT, ADMIN_SECRET,
            "token=${urlEncode(refresh)}&token_type_hint=refresh_token",
        )
        assertThat(revoke.statusCode()).isEqualTo(200)

        // 3) introspect 로 active=false 확인
        val introspect = introspectAs(
            SVC_CLIENT, SVC_SECRET,
            "token=${urlEncode(refresh)}&token_type_hint=refresh_token",
        )
        assertThat(introspect.statusCode()).isEqualTo(200)
        assertThat(introspect.body()).contains("\"active\":false")

        // 4) refresh 가 REVOKED_BY_ADMIN 으로 마킹됐는지 직접 확인
        val rt = refreshTokenRepository.findByTokenHashReadOnly(TokenHasher.sha256(refresh)).orElseThrow()
        assertThat(rt.status).isEqualTo(RefreshTokenStatus.REVOKED_BY_ADMIN)
    }

    @Test
    fun `token revoke scope 없는 client 는 403`() {
        val email = "revoke-deny+${System.nanoTime()}@example.com"
        post(
            "/api/v1/auth/register",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234"}""",
        )
        val login = post(
            "/api/v1/auth/login",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234","deviceLabel":"e2e-deny"}""",
        )
        val refresh = json(login.body(), "refreshToken")!!

        // internal-service 는 token.revoke scope 없음 → OPA 거부 → 403
        val denied = revokeAs(
            SVC_CLIENT, SVC_SECRET,
            "token=${urlEncode(refresh)}&token_type_hint=refresh_token",
        )
        assertThat(denied.statusCode()).isEqualTo(403)

        // refresh 는 그대로 ACTIVE
        val rt = refreshTokenRepository.findByTokenHashReadOnly(TokenHasher.sha256(refresh)).orElseThrow()
        assertThat(rt.status).isEqualTo(RefreshTokenStatus.ACTIVE)
    }

    @Test
    fun `알 수 없는 token 의 revoke 는 200 정보 누설 차단`() {
        val res = revokeAs(
            ADMIN_CLIENT, ADMIN_SECRET,
            "token=${urlEncode("bogus-token-for-rfc7009-spec")}",
        )
        assertThat(res.statusCode()).isEqualTo(200)
    }

    @Test
    fun `인증 없이 revoke 시도는 401`() {
        val res = http.send(
            HttpRequest.newBuilder(URI.create("${baseUrl()}/oauth2/revoke"))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("token=anything"))
                .build(),
            HttpResponse.BodyHandlers.ofString(),
        )
        assertThat(res.statusCode()).isEqualTo(401)
    }

    private fun revokeAs(clientId: String, secret: String, formBody: String): HttpResponse<String> =
        formPost("/oauth2/revoke", clientId, secret, formBody)

    private fun introspectAs(clientId: String, secret: String, formBody: String): HttpResponse<String> =
        formPost("/oauth2/introspect", clientId, secret, formBody)

    private fun formPost(
        path: String,
        clientId: String,
        secret: String,
        formBody: String,
    ): HttpResponse<String> {
        val basic = Base64.getEncoder().encodeToString("$clientId:$secret".toByteArray())
        return http.send(
            HttpRequest.newBuilder(URI.create("${baseUrl()}$path"))
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
        private const val SVC_CLIENT = "internal-service"
        private const val SVC_SECRET = "internal-service-secret-change-me"
        private const val ADMIN_CLIENT = "internal-admin"
        private const val ADMIN_SECRET = "internal-admin-secret-change-me"

        private fun json(body: String, key: String): String? {
            val prefix = "\"$key\":\""
            val start = body.indexOf(prefix)
            if (start < 0) return null
            val from = start + prefix.length
            val end = body.indexOf("\"", from)
            return if (end < 0) null else body.substring(from, end)
        }

        private fun urlEncode(s: String): String = URLEncoder.encode(s, StandardCharsets.UTF_8)
    }
}
