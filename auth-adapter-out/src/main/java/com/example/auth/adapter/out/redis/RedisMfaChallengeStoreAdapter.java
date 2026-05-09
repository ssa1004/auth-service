package com.example.auth.adapter.out.redis;

import com.example.auth.application.port.out.MfaChallengeStore;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * MFA challenge token 을 Redis 에 TTL 5분으로 보관.
 *
 * <p>토큰 자체는 CSPRNG 256bit. 키 형식은 {@code mfa:challenge:<token>}, 값은
 * {@code <tenantId>|<userId>}. 검증 시 GETDEL 로 1회 consume — replay 차단.
 */
@Component
@RequiredArgsConstructor
public class RedisMfaChallengeStoreAdapter implements MfaChallengeStore {

    private static final String PREFIX = "mfa:challenge:";
    private static final SecureRandom RNG = new SecureRandom();

    private final StringRedisTemplate redis;

    @Override
    public String issueChallenge(TenantId tenantId, UserId userId, Duration ttl) {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
        redis.opsForValue().set(PREFIX + token,
                tenantId.asString() + "|" + userId.asString(), ttl);
        return token;
    }

    @Override
    public Optional<Challenge> consume(String challengeToken) {
        String value = redis.opsForValue().getAndDelete(PREFIX + challengeToken);
        if (value == null) return Optional.empty();
        int sep = value.indexOf('|');
        if (sep <= 0) return Optional.empty();
        return Optional.of(new Challenge(
                TenantId.of(value.substring(0, sep)),
                UserId.of(value.substring(sep + 1))));
    }
}
