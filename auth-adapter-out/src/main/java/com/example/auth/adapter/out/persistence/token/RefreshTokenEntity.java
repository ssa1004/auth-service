package com.example.auth.adapter.out.persistence.token;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.token.RefreshToken;
import com.example.auth.domain.token.RefreshTokenStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
public class RefreshTokenEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @Column(name = "parent_id")
    private UUID parentId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RefreshTokenStatus status;

    @Column(name = "device_label")
    private String deviceLabel;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    protected RefreshTokenEntity() {}

    public static RefreshTokenEntity from(RefreshToken t) {
        RefreshTokenEntity e = new RefreshTokenEntity();
        e.id = t.id();
        e.tenantId = t.tenantId().value();
        e.userId = t.userId().value();
        e.tokenHash = t.tokenHash();
        e.parentId = t.parentId();
        e.status = t.status();
        e.deviceLabel = t.deviceLabel();
        e.ipAddress = t.ipAddress();
        e.issuedAt = t.issuedAt();
        e.expiresAt = t.expiresAt();
        e.lastUsedAt = t.lastUsedAt();
        return e;
    }

    public RefreshToken toDomain() {
        return new RefreshToken(
                id, TenantId.of(tenantId), UserId.of(userId),
                tokenHash, parentId, status,
                deviceLabel, ipAddress, issuedAt, expiresAt, lastUsedAt);
    }
}
