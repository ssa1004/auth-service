package com.example.auth.adapter.out.persistence.token

import com.example.auth.application.port.out.RefreshTokenRepository
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import com.example.auth.domain.token.RefreshToken
import com.example.auth.domain.token.RefreshTokenStatus
import java.time.Clock
import java.util.Optional
import org.springframework.stereotype.Repository

@Repository
class RefreshTokenRepositoryAdapter(
    private val jpa: RefreshTokenJpaRepository,
    private val clock: Clock,
) : RefreshTokenRepository {

    override fun save(token: RefreshToken): RefreshToken =
        jpa.save(RefreshTokenEntity.from(token)).toDomain()

    override fun findByTokenHash(tokenHash: String): Optional<RefreshToken> =
        // 회전 / reuse detection 경로 — 비관적 잠금으로 race 방지.
        jpa.findByTokenHashForUpdate(tokenHash).map { it.toDomain() }

    override fun findByTokenHashReadOnly(tokenHash: String): Optional<RefreshToken> =
        // introspection 등 단순 조회 — 잠금 없이.
        jpa.findByTokenHash(tokenHash).map { it.toDomain() }

    override fun findActiveByUser(tenantId: TenantId, userId: UserId): List<RefreshToken> =
        jpa.findByTenantIdAndUserIdAndStatus(
            tenantId.value, userId.value, RefreshTokenStatus.ACTIVE,
        ).map { it.toDomain() }

    override fun revokeAllForUser(tenantId: TenantId, userId: UserId): Int =
        jpa.bulkRevoke(
            tenantId.value,
            userId.value,
            listOf(RefreshTokenStatus.ACTIVE, RefreshTokenStatus.REVOKED_ROTATED),
            RefreshTokenStatus.REVOKED_REUSE_DETECTED,
            clock.instant(),
        )
}
