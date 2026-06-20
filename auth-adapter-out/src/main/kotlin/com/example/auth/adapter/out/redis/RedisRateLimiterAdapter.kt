package com.example.auth.adapter.out.redis

import com.example.auth.application.port.out.RateLimiter
import com.example.auth.application.security.AuthProperties
import io.github.bucket4j.BucketConfiguration
import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy
import io.github.bucket4j.distributed.proxy.ProxyManager
import io.github.bucket4j.redis.lettuce.Bucket4jLettuce
import io.lettuce.core.RedisClient
import jakarta.annotation.PreDestroy
import java.nio.charset.StandardCharsets
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component

/**
 * (IP, username) 기반 token bucket rate limit.
 *
 * bucket4j-lettuce CAS — atomic token bucket 을 Redis 에 분산 저장.
 * key 예: `login:<tenant>:<ip>:<email>`.
 *
 * `auth.rate-limit.redis-enabled` 가 true (default, 운영) 일 때만 이 빈이 생성됩니다.
 * false (dev/local) 면 본 빈은 만들어지지 않으므로 부팅 시 Lettuce 가 Redis 로 연결을
 * 시도하지 않고, 대신 [InMemoryRateLimiterAdapter] 가 in-process token bucket 으로
 * 동작합니다 — Redis 등 외부 인프라 없이 부팅 가능 (multi-instance 분산은 운영 prod 경로만).
 */
@Component
@Profile("!e2e")
@ConditionalOnProperty(
    prefix = "auth.rate-limit",
    name = ["redis-enabled"],
    havingValue = "true",
    matchIfMissing = true,
)
class RedisRateLimiterAdapter(
    @Value("\${spring.data.redis.url:redis://localhost:6379}") redisUrl: String,
    properties: AuthProperties,
) : RateLimiter {

    private val redisClient: RedisClient = RedisClient.create(redisUrl)
    private val proxyManager: ProxyManager<ByteArray> = Bucket4jLettuce.casBasedBuilder(redisClient)
        .expirationAfterWrite(
            ExpirationAfterWriteStrategy.basedOnTimeForRefillingBucketUpToMax(
                properties.loginRateWindow.multipliedBy(2),
            ),
        )
        .build()
    private val configuration: BucketConfiguration = run {
        val window = properties.loginRateWindow
        val burst = properties.loginRateBurst.toLong()
        BucketConfiguration.builder()
            .addLimit { limit -> limit.capacity(burst).refillGreedy(burst, window) }
            .build()
    }

    override fun tryConsume(key: String): Boolean {
        val bucket = proxyManager.builder().build(key.toByteArray(StandardCharsets.UTF_8)) { configuration }
        return bucket.tryConsume(1)
    }

    @PreDestroy
    fun close() {
        try {
            redisClient.shutdown()
        } catch (ignored: Exception) {
            // ignored
        }
    }
}
