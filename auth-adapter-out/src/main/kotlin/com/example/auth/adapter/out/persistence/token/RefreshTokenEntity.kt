package com.example.auth.adapter.out.persistence.token

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import com.example.auth.domain.token.RefreshToken
import com.example.auth.domain.token.RefreshTokenStatus
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "refresh_tokens")
class RefreshTokenEntity {

    @Id
    private var id: UUID = UUID(0, 0)

    @Column(name = "tenant_id", nullable = false)
    private var tenantId: UUID = UUID(0, 0)

    @Column(name = "user_id", nullable = false)
    private var userId: UUID = UUID(0, 0)

    @Column(name = "token_hash", nullable = false, unique = true)
    private var tokenHash: String = ""

    @Column(name = "parent_id")
    private var parentId: UUID? = null

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private var status: RefreshTokenStatus = RefreshTokenStatus.ACTIVE

    @Column(name = "device_label")
    private var deviceLabel: String? = null

    @Column(name = "ip_address")
    private var ipAddress: String? = null

    @Column(name = "issued_at", nullable = false)
    private var issuedAt: Instant = Instant.EPOCH

    @Column(name = "expires_at", nullable = false)
    private var expiresAt: Instant = Instant.EPOCH

    @Column(name = "last_used_at")
    private var lastUsedAt: Instant? = null

    fun toDomain(): RefreshToken = RefreshToken(
        id, TenantId.of(tenantId), UserId.of(userId),
        tokenHash, parentId, status,
        deviceLabel, ipAddress, issuedAt, expiresAt, lastUsedAt,
    )

    companion object {
        @JvmStatic
        fun from(t: RefreshToken): RefreshTokenEntity = RefreshTokenEntity().apply {
            id = t.id
            tenantId = t.tenantId.value
            userId = t.userId.value
            tokenHash = t.tokenHash
            parentId = t.parentId
            status = t.status
            deviceLabel = t.deviceLabel
            ipAddress = t.ipAddress
            issuedAt = t.issuedAt
            expiresAt = t.expiresAt
            lastUsedAt = t.lastUsedAt
        }
    }
}
