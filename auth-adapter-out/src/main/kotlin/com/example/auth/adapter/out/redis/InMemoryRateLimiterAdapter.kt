package com.example.auth.adapter.out.redis

import com.example.auth.application.port.out.RateLimiter
import com.example.auth.application.security.AuthProperties
import io.github.bucket4j.Bucket
import java.util.concurrent.ConcurrentHashMap
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component

/**
 * Redis 없이 동작하는 in-process token bucket rate limiter — dev/local 부팅 전용.
 *
 * `auth.rate-limit.redis-enabled=false` 일 때 [RedisRateLimiterAdapter] 대신 활성화됩니다.
 * bucket4j 의 local(LockFree) bucket 을 key 별로 [ConcurrentHashMap] 에 보관 — 운영의
 * Redis CAS 구현과 동일한 token-bucket 의미론(capacity = burst, greedy refill over window)을
 * 그대로 갖는 *실제* 제한기입니다. brute-force 보호가 dev 에서도 동일하게 동작합니다.
 *
 * 차이점은 분산이 아니라 인스턴스-로컬이라는 점뿐 — 단일 노드로 띄우는 dev/local 에서는
 * 충분하며, 운영(default, redis-enabled=true)은 영향받지 않습니다.
 *
 * 메모리 누수 방지: key 가 무한히 늘 수 있으므로 상한을 두고, 도달 시 가장 단순하게
 * 전체를 비웁니다. login key 는 (tenant, ip, email) 조합이라 정상 트래픽에서는 상한에
 * 거의 닿지 않습니다.
 */
@Component
@Profile("!e2e")
@ConditionalOnProperty(
    prefix = "auth.rate-limit",
    name = ["redis-enabled"],
    havingValue = "false",
)
class InMemoryRateLimiterAdapter(
    properties: AuthProperties,
) : RateLimiter {

    private val window = properties.loginRateWindow
    private val burst = properties.loginRateBurst.toLong()
    private val buckets = ConcurrentHashMap<String, Bucket>()

    override fun tryConsume(key: String): Boolean {
        if (buckets.size >= MAX_KEYS && !buckets.containsKey(key)) {
            buckets.clear()
        }
        val bucket = buckets.computeIfAbsent(key) {
            Bucket.builder()
                .addLimit { limit -> limit.capacity(burst).refillGreedy(burst, window) }
                .build()
        }
        return bucket.tryConsume(1)
    }

    private companion object {
        const val MAX_KEYS = 100_000
    }
}
