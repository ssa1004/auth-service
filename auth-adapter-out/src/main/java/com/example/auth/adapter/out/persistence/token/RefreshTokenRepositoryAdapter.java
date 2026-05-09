package com.example.auth.adapter.out.persistence.token;

import com.example.auth.application.port.out.RefreshTokenRepository;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.token.RefreshToken;
import com.example.auth.domain.token.RefreshTokenStatus;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class RefreshTokenRepositoryAdapter implements RefreshTokenRepository {

    private final RefreshTokenJpaRepository jpa;
    private final Clock clock;

    @Override
    public RefreshToken save(RefreshToken token) {
        return jpa.save(RefreshTokenEntity.from(token)).toDomain();
    }

    @Override
    public Optional<RefreshToken> findByTokenHash(String tokenHash) {
        // 회전 / reuse detection 경로 — 비관적 잠금으로 race 방지.
        return jpa.findByTokenHashForUpdate(tokenHash).map(RefreshTokenEntity::toDomain);
    }

    @Override
    public List<RefreshToken> findActiveByUser(TenantId tenantId, UserId userId) {
        return jpa.findByTenantIdAndUserIdAndStatus(
                        tenantId.value(), userId.value(), RefreshTokenStatus.ACTIVE)
                .stream()
                .map(RefreshTokenEntity::toDomain)
                .toList();
    }

    @Override
    public int revokeAllForUser(TenantId tenantId, UserId userId) {
        return jpa.bulkRevoke(
                tenantId.value(),
                userId.value(),
                List.of(RefreshTokenStatus.ACTIVE, RefreshTokenStatus.REVOKED_ROTATED),
                RefreshTokenStatus.REVOKED_REUSE_DETECTED,
                clock.instant());
    }
}
