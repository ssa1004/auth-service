package com.example.auth.bootstrap

import com.example.auth.adapter.out.redis.InMemoryRateLimiterAdapter
import com.example.auth.application.security.AuthProperties
import java.time.Duration
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * dev/local 부팅용 in-memory rate limiter 가 *실제로* 제한하는지 검증.
 *
 * Redis 없이도 토큰 버킷 의미론(capacity=burst, 초과 시 거부)이 동일하게 동작함을 확인 —
 * dev 에서도 brute-force 보호가 비활성화되지 않음을 보장합니다.
 */
class InMemoryRateLimiterAdapterTest {

    private fun props(burst: Int): AuthProperties = AuthProperties(
        Duration.ofMinutes(15),
        Duration.ofDays(30),
        Duration.ofSeconds(5),
        12,
        burst,
        Duration.ofMinutes(1),
        "https://auth.example.com",
        "auth-service",
        emptyList(),
        AuthProperties.Opa.embedded(),
    )

    @Test
    fun `burst 만큼 허용하고 그 다음 요청은 거부한다`() {
        val limiter = InMemoryRateLimiterAdapter(props(burst = 3))
        val key = "login:default:127.0.0.1:user@example.com"

        assertThat(limiter.tryConsume(key)).isTrue()
        assertThat(limiter.tryConsume(key)).isTrue()
        assertThat(limiter.tryConsume(key)).isTrue()
        // capacity 소진 — 다음 요청은 거부 (refill 은 window 단위라 즉시 회복 안 됨).
        assertThat(limiter.tryConsume(key)).isFalse()
    }

    @Test
    fun `key 별로 버킷이 독립적이다`() {
        val limiter = InMemoryRateLimiterAdapter(props(burst = 1))

        assertThat(limiter.tryConsume("login:default:1.1.1.1:a@x.com")).isTrue()
        assertThat(limiter.tryConsume("login:default:1.1.1.1:a@x.com")).isFalse()
        // 다른 key 는 영향받지 않음.
        assertThat(limiter.tryConsume("login:default:2.2.2.2:b@x.com")).isTrue()
    }
}
