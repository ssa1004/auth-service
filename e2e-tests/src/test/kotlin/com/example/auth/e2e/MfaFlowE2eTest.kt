package com.example.auth.e2e

import com.example.auth.application.port.out.MfaSecretCipher
import com.example.auth.application.port.out.MfaSecretRepository
import com.example.auth.application.port.out.TenantRepository
import com.example.auth.application.port.out.TotpVerifier
import com.example.auth.application.port.out.UserRepository
import com.example.auth.domain.mfa.MfaMethod
import com.example.auth.domain.mfa.MfaSecret
import com.example.auth.domain.tenant.Tenant
import com.example.auth.domain.user.User
import dev.samstevens.totp.code.DefaultCodeGenerator
import dev.samstevens.totp.time.SystemTimeProvider
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder

/**
 * MFA 흐름 e2e — 비밀번호 통과 → 401 + mfa_token → /verify-mfa 로 access 발급.
 *
 * 잘못된 코드는 InvalidCredentials. challenge 토큰은 1회 consume.
 */
class MfaFlowE2eTest : AbstractE2eTest() {

    @Autowired
    lateinit var userRepository: UserRepository

    @Autowired
    lateinit var tenantRepository: TenantRepository

    @Autowired
    lateinit var mfaSecretRepository: MfaSecretRepository

    @Autowired
    lateinit var mfaSecretCipher: MfaSecretCipher

    @Autowired
    lateinit var totpVerifier: TotpVerifier

    private val http: HttpClient = HttpClient.newHttpClient()

    @Test
    fun `mfa 활성 사용자는 login 시 mfa required 그 후 verify 로 access 발급`() {
        // 1) seed: tenant + user with MFA enabled
        val tenant = tenantRepository.findBySlug("acme")
            .orElseGet { tenantRepository.save(Tenant.create("acme", "ACME", Instant.now())) }
        val email = "mfa-${System.nanoTime()}@example.com"
        val hash = BCryptPasswordEncoder(4).encode("longenoughpw1234")
        val u = userRepository.save(
            User.register(tenant.id, email, hash, Instant.now())
                .markVerified(Instant.now())
                .enableMfa(Instant.now()),
        )
        val secret = totpVerifier.generateSecret()
        mfaSecretRepository.save(
            MfaSecret.enroll(u.id, mfaSecretCipher.encrypt(secret), MfaMethod.TOTP, Instant.now())
                .confirm(Instant.now()),
        )

        // 2) login → 401 + mfa_token
        val login = post(
            "/api/v1/auth/login",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234","deviceLabel":"e2e"}""",
        )
        assertThat(login.statusCode()).isEqualTo(401)
        assertThat(login.headers().firstValue("X-Mfa-Required")).contains("true")
        val mfaToken = json(login.body(), "mfaToken")
        assertThat(mfaToken).isNotBlank

        // 3) 잘못된 코드 → 401
        val wrong = post(
            "/api/v1/auth/verify-mfa",
            """{"mfaToken":"$mfaToken","code":"000000","deviceLabel":"e2e"}""",
        )
        assertThat(wrong.statusCode()).isEqualTo(401)

        // 4) 새 challenge 발급 (이전은 consume 되어 사라짐) — 다시 login 호출.
        val login2 = post(
            "/api/v1/auth/login",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234","deviceLabel":"e2e"}""",
        )
        val freshMfaToken = json(login2.body(), "mfaToken")

        // 5) 올바른 TOTP 생성 + verify
        val gen = DefaultCodeGenerator()
        val bucket = SystemTimeProvider().time / 30
        val code = gen.generate(secret, bucket)
        val ok = post(
            "/api/v1/auth/verify-mfa",
            """{"mfaToken":"$freshMfaToken","code":"$code","deviceLabel":"e2e"}""",
        )
        assertThat(ok.statusCode()).isEqualTo(200)
        assertThat(json(ok.body(), "accessToken")).startsWith("ey")
    }

    @Test
    fun `mfa challenge replay 차단 같은 token 으로 2번 verify 불가`() {
        val tenant = tenantRepository.findBySlug("acme")
            .orElseGet { tenantRepository.save(Tenant.create("acme", "ACME", Instant.now())) }
        val email = "mfa-replay-${System.nanoTime()}@example.com"
        val hash = BCryptPasswordEncoder(4).encode("longenoughpw1234")
        val u = userRepository.save(
            User.register(tenant.id, email, hash, Instant.now())
                .markVerified(Instant.now())
                .enableMfa(Instant.now()),
        )
        val secret = totpVerifier.generateSecret()
        mfaSecretRepository.save(
            MfaSecret.enroll(u.id, mfaSecretCipher.encrypt(secret), MfaMethod.TOTP, Instant.now())
                .confirm(Instant.now()),
        )

        val login = post(
            "/api/v1/auth/login",
            """{"tenantSlug":"acme","email":"$email","password":"longenoughpw1234","deviceLabel":"e2e"}""",
        )
        val mfaToken = json(login.body(), "mfaToken")

        val gen = DefaultCodeGenerator()
        val bucket = SystemTimeProvider().time / 30
        val code = gen.generate(secret, bucket)

        val first = post(
            "/api/v1/auth/verify-mfa",
            """{"mfaToken":"$mfaToken","code":"$code","deviceLabel":"e2e"}""",
        )
        assertThat(first.statusCode()).isEqualTo(200)

        // 같은 mfaToken 으로 다시 → consume 되어 401
        val second = post(
            "/api/v1/auth/verify-mfa",
            """{"mfaToken":"$mfaToken","code":"$code","deviceLabel":"e2e"}""",
        )
        assertThat(second.statusCode()).isEqualTo(401)
    }

    private fun post(path: String, body: String): HttpResponse<String> =
        http.send(
            HttpRequest.newBuilder(URI.create("${baseUrl()}$path"))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
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
