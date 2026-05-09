package com.example.auth.application.security;

import java.time.Duration;
import java.util.Objects;

/**
 * 로그인 / refresh 결과로 호출자에게 한 번 노출되는 두 토큰. refreshToken 평문은 이 객체가
 * 응답으로 직렬화된 직후 삭제됩니다 — DB / 로그 어디에도 평문이 남으면 안 됩니다.
 */
public record AuthTokens(
        String accessToken,
        String refreshToken,
        String tokenType,
        Duration accessTokenTtl,
        Duration refreshTokenTtl) {

    public AuthTokens {
        Objects.requireNonNull(accessToken);
        Objects.requireNonNull(refreshToken);
        Objects.requireNonNull(tokenType);
        Objects.requireNonNull(accessTokenTtl);
        Objects.requireNonNull(refreshTokenTtl);
    }

    public static AuthTokens bearer(
            String accessToken,
            String refreshToken,
            Duration accessTokenTtl,
            Duration refreshTokenTtl) {
        return new AuthTokens(accessToken, refreshToken, "Bearer", accessTokenTtl, refreshTokenTtl);
    }

    /** 디버그 / 로그 출력 시 평문 token 노출 방지. */
    @Override
    public String toString() {
        return "AuthTokens{tokenType=" + tokenType
                + ", accessTokenTtl=" + accessTokenTtl
                + ", refreshTokenTtl=" + refreshTokenTtl + "}";
    }
}
