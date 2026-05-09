package com.example.auth.adapter.out.persistence.token;

import com.example.auth.domain.token.RefreshTokenStatus;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenJpaRepository extends JpaRepository<RefreshTokenEntity, UUID> {

    /**
     * reuse detection 의 핵심 — 회전 시점에 같은 hash 로 동시에 두 요청이 들어와도 한쪽만
     * 회전되도록 비관적 잠금. (READ COMMITTED 기본 격리 수준에서 race 방지)
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from RefreshTokenEntity t where t.tokenHash = :hash")
    Optional<RefreshTokenEntity> findByTokenHashForUpdate(@Param("hash") String hash);

    Optional<RefreshTokenEntity> findByTokenHash(String hash);

    List<RefreshTokenEntity> findByTenantIdAndUserIdAndStatus(
            UUID tenantId, UUID userId, RefreshTokenStatus status);

    @Modifying
    @Query("""
            update RefreshTokenEntity t
               set t.status = :revoked, t.lastUsedAt = :now
             where t.tenantId = :tenantId
               and t.userId = :userId
               and t.status in (:targetStatuses)
            """)
    int bulkRevoke(
            @Param("tenantId") UUID tenantId,
            @Param("userId") UUID userId,
            @Param("targetStatuses") List<RefreshTokenStatus> targetStatuses,
            @Param("revoked") RefreshTokenStatus revoked,
            @Param("now") Instant now);
}
