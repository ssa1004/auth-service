package com.example.auth.application.security

import java.net.URI
import java.time.Duration

/**
 * 보안 정책 단일 진입점. 코드 곳곳에 흩어지면 정책 변경이 누락되므로 한 곳에 모읍니다.
 *
 * 운영에서는 `@ConfigurationProperties` 로 application.yml 에서 주입 (bootstrap).
 * 단위 테스트에서는 [defaults] 로 상수 값을 사용.
 */
@JvmRecord
data class AuthProperties(
    val accessTokenTtl: Duration,
    val refreshTokenTtl: Duration,
    val refreshReuseGracePeriod: Duration,
    val bcryptCost: Int,
    val loginRateBurst: Int,
    val loginRateWindow: Duration,
    val jwtIssuer: String,
    val mfaIssuer: String,
    val trustedProxies: List<String>,
    val opa: Opa,
) {

    /**
     * OPA wiring (ADR-0016).
     *
     * @param mode        embedded → in-process Java 평가기, sidecar → REST OPA daemon.
     * @param baseUrl     sidecar 모드에서 사용. 보통 localhost:8181.
     * @param callTimeout REST 호출 timeout. OPA 정상 응답이 ms 대라 100ms 이내 권장.
     */
    @JvmRecord
    data class Opa(val mode: String, val baseUrl: URI?, val callTimeout: Duration) {
        companion object {
            @JvmStatic
            fun embedded(): Opa = Opa("embedded", null, Duration.ofMillis(100))
        }
    }

    companion object {
        @JvmStatic
        fun defaults(): AuthProperties = AuthProperties(
            Duration.ofMinutes(15),
            Duration.ofDays(30),
            Duration.ofSeconds(5),
            12,
            10,
            Duration.ofMinutes(1),
            "https://auth.example.com",
            "auth-service",
            emptyList(),
            Opa.embedded(),
        )
    }
}
