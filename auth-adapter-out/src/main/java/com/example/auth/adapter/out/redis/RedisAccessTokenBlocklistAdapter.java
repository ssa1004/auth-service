package com.example.auth.adapter.out.redis;

import com.example.auth.application.port.out.AccessTokenBlocklist;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * RFC 7009 admin revoke 시 access JWT 의 jti 를 Redis 에 보관 (ADR-0017 / 0018).
 *
 * <p>키 형식 {@code at:revoked:<jti>}, 값은 의미 없음 ("1"). TTL = 토큰의 남은 유효시간으로
 * 잡아 만료 후에는 자동 정리. 분산 인스턴스가 같은 Redis 를 바라보므로 어느 노드에서 revoke
 * 해도 즉시 모든 노드의 introspection 호출이 일관된 결과를 반환합니다.
 *
 * <p>JWT 의 jti 가 없으면 본 블록리스트로 차단 불가능하므로, 발급기는 항상 {@code jti}
 * claim 을 포함시켜야 합니다 ({@code NimbusAccessTokenIssuerAdapter} 가 UUID 로 보장).
 */
@Component
@RequiredArgsConstructor
public class RedisAccessTokenBlocklistAdapter implements AccessTokenBlocklist {

    private static final String PREFIX = "at:revoked:";

    private final StringRedisTemplate redis;

    @Override
    public void add(String jwtId, Duration ttl) {
        if (jwtId == null || jwtId.isBlank()) return;
        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            // 이미 만료된 토큰은 굳이 적재하지 않음 — JWT 자체 검증에서 걸러짐.
            return;
        }
        redis.opsForValue().set(PREFIX + jwtId, "1", ttl);
    }

    @Override
    public boolean contains(String jwtId) {
        if (jwtId == null || jwtId.isBlank()) return false;
        Boolean exists = redis.hasKey(PREFIX + jwtId);
        return Boolean.TRUE.equals(exists);
    }
}
