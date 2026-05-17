package com.example.auth.adapter.out.security

import com.example.auth.application.port.out.RefreshTokenGenerator
import java.security.SecureRandom
import java.util.Base64
import org.springframework.stereotype.Component

/**
 * CSPRNG 기반 256bit refresh token 평문 생성. URL-safe base64 인코딩.
 */
@Component
class SecureRandomRefreshTokenGenerator : RefreshTokenGenerator {

    override fun generate(): String {
        val buf = ByteArray(32)
        RNG.nextBytes(buf)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf)
    }

    private companion object {
        val RNG = SecureRandom()
    }
}
