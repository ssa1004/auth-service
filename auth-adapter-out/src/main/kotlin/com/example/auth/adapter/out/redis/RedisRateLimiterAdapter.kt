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
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component

/**
 * (IP, username) 기반 token bucket rate limit.
 *
 * bucket4j-lettuce CAS — atomic token bucket 을 Redis 에 분산 저장.
 * key 예: `login:<tenant>:<ip>:<email>`.
 */
@Component
@Profile("!e2e")
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
