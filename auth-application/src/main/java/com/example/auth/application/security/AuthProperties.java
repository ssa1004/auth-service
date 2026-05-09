package com.example.auth.application.security;

import java.time.Duration;

/**
 * 보안 정책 단일 진입점. 코드 곳곳에 흩어지면 정책 변경이 누락되므로 한 곳에 모읍니다.
 *
 * <p>운영에서는 {@code @ConfigurationProperties} 로 application.yml 에서 주입 (bootstrap).
 * 단위 테스트에서는 {@link #defaults()} 로 상수 값을 사용.
 */
public record AuthProperties(
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        Duration refreshReuseGracePeriod,
        int bcryptCost,
        int loginRateBurst,
        Duration loginRateWindow,
        String jwtIssuer,
        String mfaIssuer) {

    public static AuthProperties defaults() {
        return new AuthProperties(
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                Duration.ofSeconds(5),
                12,
                10,
                Duration.ofMinutes(1),
                "https://auth.example.com",
                "auth-service");
    }
}
