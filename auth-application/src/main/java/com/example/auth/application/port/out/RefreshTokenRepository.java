package com.example.auth.application.port.out;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.token.RefreshToken;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository {

    RefreshToken save(RefreshToken token);

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findActiveByUser(TenantId tenantId, UserId userId);

    /**
     * 사용자의 모든 ACTIVE / ROTATED refresh 를 한 번에 REVOKED_REUSE_DETECTED 로 마킹.
     * 호출 시점은 reuse 가 탐지된 직후이며 audit log 가 남아야 합니다 (호출자 책임).
     */
    int revokeAllForUser(TenantId tenantId, UserId userId);
}
