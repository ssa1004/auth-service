package com.example.auth.adapter.in.rest;

import com.example.auth.application.security.AuthTokens;

/**
 * 로그인 / refresh / MFA 검증 응답. snake_case 는 OAuth2 관례.
 *
 * <p>refreshToken 평문은 응답으로 한 번만 노출, 호출자는 즉시 안전한 저장소 (httpOnly
 * cookie / OS keychain) 에 보관하고 우리 서버는 hash 만 보관합니다.
 */
public record TokenResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        long refreshExpiresIn,
        String mfaToken) {

    public static TokenResponse from(AuthTokens t) {
        return new TokenResponse(
                t.accessToken(),
                t.refreshToken(),
                t.tokenType(),
                t.accessTokenTtl().toSeconds(),
                t.refreshTokenTtl().toSeconds(),
                null);
    }

    public static TokenResponse mfaRequired(String mfaChallengeToken) {
        return new TokenResponse(null, null, null, 0, 0, mfaChallengeToken);
    }
}
