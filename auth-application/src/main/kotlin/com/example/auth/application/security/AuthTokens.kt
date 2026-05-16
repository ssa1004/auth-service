package com.example.auth.application.security

import java.time.Duration

/**
 * 로그인 / refresh 결과로 호출자에게 한 번 노출되는 두 토큰. refreshToken 평문은 이 객체가
 * 응답으로 직렬화된 직후 삭제됩니다 — DB / 로그 어디에도 평문이 남으면 안 됩니다.
 */
@JvmRecord
data class AuthTokens(
    val accessToken: String,
    val refreshToken: String,
    val tokenType: String,
    val accessTokenTtl: Duration,
    val refreshTokenTtl: Duration,
) {

    /** 디버그 / 로그 출력 시 평문 token 노출 방지. */
    override fun toString(): String =
        "AuthTokens{tokenType=$tokenType, accessTokenTtl=$accessTokenTtl, refreshTokenTtl=$refreshTokenTtl}"

    companion object {
        @JvmStatic
        fun bearer(
            accessToken: String,
            refreshToken: String,
            accessTokenTtl: Duration,
            refreshTokenTtl: Duration,
        ): AuthTokens = AuthTokens(accessToken, refreshToken, "Bearer", accessTokenTtl, refreshTokenTtl)
    }
}
