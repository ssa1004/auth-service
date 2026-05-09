package com.example.auth.adapter.out.redis;

import com.example.auth.application.port.out.RateLimiter;
import com.example.auth.application.security.AuthProperties;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;
import jakarta.annotation.PreDestroy;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * (IP, username) 기반 token bucket rate limit.
 *
 * <p>bucket4j-lettuce CAS — atomic token bucket 을 Redis 에 분산 저장.
 * key 예: {@code login:<tenant>:<ip>:<email>}.
 */
@Component
@Profile("!e2e")
public class RedisRateLimiterAdapter implements RateLimiter {

    private final RedisClient redisClient;
    private final ProxyManager<byte[]> proxyManager;
    private final BucketConfiguration configuration;

    public RedisRateLimiterAdapter(
            @Value("${spring.data.redis.url:redis://localhost:6379}") String redisUrl,
            AuthProperties properties) {
        this.redisClient = RedisClient.create(redisUrl);
        this.proxyManager = LettuceBasedProxyManager.builderFor(redisClient)
                .withExpirationStrategy(ExpirationAfterWriteStrategy
                        .basedOnTimeForRefillingBucketUpToMax(properties.loginRateWindow().multipliedBy(2)))
                .build();
        Duration window = properties.loginRateWindow();
        long burst = properties.loginRateBurst();
        this.configuration = BucketConfiguration.builder()
                .addLimit(limit -> limit.capacity(burst).refillGreedy(burst, window))
                .build();
    }

    @Override
    public boolean tryConsume(String key) {
        var bucket = proxyManager.builder().build(key.getBytes(StandardCharsets.UTF_8), () -> configuration);
        return bucket.tryConsume(1);
    }

    @PreDestroy
    public void close() {
        try { redisClient.shutdown(); } catch (Exception ignored) { }
    }
}
