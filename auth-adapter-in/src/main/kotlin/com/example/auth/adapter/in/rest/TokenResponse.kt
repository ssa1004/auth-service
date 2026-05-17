package com.example.auth.adapter.`in`.rest

import com.example.auth.application.security.AuthTokens

/**
 * 로그인 / refresh / MFA 검증 응답. snake_case 는 OAuth2 관례.
 *
 * refreshToken 평문은 응답으로 한 번만 노출, 호출자는 즉시 안전한 저장소 (httpOnly
 * cookie / OS keychain) 에 보관하고 우리 서버는 hash 만 보관합니다.
 */
@JvmRecord
data class TokenResponse(
    val accessToken: String?,
    val refreshToken: String?,
    val tokenType: String?,
    val expiresIn: Long,
    val refreshExpiresIn: Long,
    val mfaToken: String?,
) {

    companion object {

        @JvmStatic
        fun from(t: AuthTokens): TokenResponse = TokenResponse(
            t.accessToken,
            t.refreshToken,
            t.tokenType,
            t.accessTokenTtl.toSeconds(),
            t.refreshTokenTtl.toSeconds(),
            null,
        )

        @JvmStatic
        fun mfaRequired(mfaChallengeToken: String): TokenResponse =
            TokenResponse(null, null, null, 0, 0, mfaChallengeToken)
    }
}
