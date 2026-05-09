package com.example.auth.application.port.out;

/**
 * (IP, username) 기반 token bucket rate limit. brute-force 차단.
 *
 * <p>구현체는 Redis 기반 bucket4j (adapter-out). application 은 try-consume 의 결과만
 * 받아 의사결정합니다.
 */
public interface RateLimiter {

    /**
     * @return true 면 한 번 소비 (요청 허용), false 면 한도 초과 (요청 거부).
     */
    boolean tryConsume(String key);
}
