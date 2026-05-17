package com.example.auth.adapter.out.totp

import com.example.auth.application.port.out.TotpVerifier
import dev.samstevens.totp.code.CodeGenerator
import dev.samstevens.totp.code.CodeVerifier
import dev.samstevens.totp.code.DefaultCodeGenerator
import dev.samstevens.totp.code.DefaultCodeVerifier
import dev.samstevens.totp.code.HashingAlgorithm
import dev.samstevens.totp.secret.DefaultSecretGenerator
import dev.samstevens.totp.secret.SecretGenerator
import dev.samstevens.totp.time.SystemTimeProvider
import dev.samstevens.totp.time.TimeProvider
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import org.springframework.stereotype.Component

/**
 * RFC 6238 TOTP — dev.samstevens.totp 라이브러리. SHA1 / 30s / 6 digits
 * (Google Authenticator 호환). window = ±1 step (=30초 시계 어긋남 허용).
 */
@Component
class SamstevensTotpAdapter : TotpVerifier {

    private val secretGenerator: SecretGenerator = DefaultSecretGenerator(32)
    private val timeProvider: TimeProvider = SystemTimeProvider()
    private val codeGenerator: CodeGenerator = DefaultCodeGenerator(HashingAlgorithm.SHA1, 6)
    private val verifier: CodeVerifier = DefaultCodeVerifier(codeGenerator, timeProvider).apply {
        setTimePeriod(30)
        setAllowedTimePeriodDiscrepancy(1)
    }

    override fun generateSecret(): String = secretGenerator.generate()

    override fun otpAuthUrl(label: String, issuer: String, secret: String): String =
        "otpauth://totp/${urlEncode(issuer)}:${urlEncode(label)}" +
            "?secret=$secret&issuer=${urlEncode(issuer)}"

    override fun verify(secret: String, code: String): Boolean =
        verifier.isValidCode(secret, code)

    private companion object {
        fun urlEncode(s: String): String = URLEncoder.encode(s, StandardCharsets.UTF_8)
    }
}
