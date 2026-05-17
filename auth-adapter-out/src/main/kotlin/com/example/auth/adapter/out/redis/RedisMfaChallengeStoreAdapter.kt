package com.example.auth.adapter.out.redis

import com.example.auth.application.port.out.MfaChallengeStore
import com.example.auth.application.port.out.MfaChallengeStore.Challenge
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import java.security.SecureRandom
import java.time.Duration
import java.util.Base64
import java.util.Optional
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component

/**
 * MFA challenge token 을 Redis 에 TTL 5분으로 보관.
 *
 * 토큰 자체는 CSPRNG 256bit. 키 형식은 `mfa:challenge:<token>`, 값은
 * `<tenantId>|<userId>`. 검증 시 GETDEL 로 1회 consume — replay 차단.
 */
@Component
class RedisMfaChallengeStoreAdapter(
    private val redis: StringRedisTemplate,
) : MfaChallengeStore {

    override fun issueChallenge(tenantId: TenantId, userId: UserId, ttl: Duration): String {
        val buf = ByteArray(32)
        RNG.nextBytes(buf)
        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(buf)
        redis.opsForValue().set(
            PREFIX + token,
            "${tenantId.asString()}|${userId.asString()}",
            ttl,
        )
        return token
    }

    override fun consume(challengeToken: String): Optional<Challenge> {
        val value = redis.opsForValue().getAndDelete(PREFIX + challengeToken)
            ?: return Optional.empty()
        val sep = value.indexOf('|')
        if (sep <= 0) return Optional.empty()
        return Optional.of(
            Challenge(
                TenantId.of(value.substring(0, sep)),
                UserId.of(value.substring(sep + 1)),
            ),
        )
    }

    private companion object {
        const val PREFIX = "mfa:challenge:"
        val RNG = SecureRandom()
    }
}
