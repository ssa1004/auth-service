package com.example.auth.application.port.out

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import com.example.auth.domain.token.RefreshToken
import java.util.Optional

interface RefreshTokenRepository {

    fun save(token: RefreshToken): RefreshToken

    fun findByTokenHash(tokenHash: String): Optional<RefreshToken>

    /**
     * introspection 처럼 잠금이 필요 없는 단순 조회용. [findByTokenHash]
     * 가 회전 / reuse detection 경로에서 비관적 잠금을 거는 것과 달리, 본 메서드는 read-only
     * 트랜잭션에서 사용해야 합니다.
     */
    fun findByTokenHashReadOnly(tokenHash: String): Optional<RefreshToken>

    fun findActiveByUser(tenantId: TenantId, userId: UserId): List<RefreshToken>

    /**
     * 사용자의 모든 ACTIVE / ROTATED refresh 를 한 번에 REVOKED_REUSE_DETECTED 로 마킹.
     * 호출 시점은 reuse 가 탐지된 직후이며 audit log 가 남아야 합니다 (호출자 책임).
     */
    fun revokeAllForUser(tenantId: TenantId, userId: UserId): Int
}
