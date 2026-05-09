package com.example.auth.domain.token;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Refresh token aggregate.
 *
 * <p>핵심 규칙:
 * <ul>
 *   <li>도메인 객체에는 token 평문이 들어오지 않습니다 — {@code tokenHash} 만 보관 (SHA-256).
 *       탈취 가정 하에 DB 가 새 나가도 직접 사용 불가능.</li>
 *   <li>한 토큰은 한 번만 사용 가능 (rotation). 사용되면 {@code REVOKED_ROTATED} 가 되고
 *       새 토큰의 {@code parentId} 로 연결됩니다.</li>
 *   <li>이미 회전된 토큰이 다시 들어오면 reuse — Auth0 패턴에 따라 사용자의 모든 토큰을
 *       강제 revoke. (도메인은 상태 천이 책임만, 일괄 revoke 는 application 의 책임)</li>
 * </ul>
 */
public final class RefreshToken {

    private final UUID id;
    private final TenantId tenantId;
    private final UserId userId;
    private final String tokenHash;
    private final UUID parentId;
    private final RefreshTokenStatus status;
    private final String deviceLabel;
    private final String ipAddress;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private final Instant lastUsedAt;

    public RefreshToken(
            UUID id,
            TenantId tenantId,
            UserId userId,
            String tokenHash,
            UUID parentId,
            RefreshTokenStatus status,
            String deviceLabel,
            String ipAddress,
            Instant issuedAt,
            Instant expiresAt,
            Instant lastUsedAt) {
        this.id = Objects.requireNonNull(id);
        this.tenantId = Objects.requireNonNull(tenantId);
        this.userId = Objects.requireNonNull(userId);
        if (tokenHash == null || tokenHash.length() < 32) {
            throw new IllegalArgumentException(
                    "tokenHash 는 hash 결과 (>= 32자) 여야 합니다 — 평문 token 금지");
        }
        this.tokenHash = tokenHash;
        this.parentId = parentId;
        this.status = Objects.requireNonNull(status);
        this.deviceLabel = deviceLabel;
        this.ipAddress = ipAddress;
        this.issuedAt = Objects.requireNonNull(issuedAt);
        this.expiresAt = Objects.requireNonNull(expiresAt);
        this.lastUsedAt = lastUsedAt;
        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("expiresAt 은 issuedAt 보다 미래여야 합니다");
        }
    }

    public static RefreshToken issue(
            TenantId tenantId,
            UserId userId,
            String tokenHash,
            UUID parentId,
            String deviceLabel,
            String ipAddress,
            Instant issuedAt,
            Instant expiresAt) {
        return new RefreshToken(
                UUID.randomUUID(),
                tenantId,
                userId,
                tokenHash,
                parentId,
                RefreshTokenStatus.ACTIVE,
                deviceLabel,
                ipAddress,
                issuedAt,
                expiresAt,
                null);
    }

    public RefreshToken markRotated(Instant now) {
        return new RefreshToken(
                id, tenantId, userId, tokenHash, parentId,
                RefreshTokenStatus.REVOKED_ROTATED,
                deviceLabel, ipAddress, issuedAt, expiresAt, now);
    }

    public RefreshToken markRevokedByUser(Instant now) {
        return new RefreshToken(
                id, tenantId, userId, tokenHash, parentId,
                RefreshTokenStatus.REVOKED_BY_USER,
                deviceLabel, ipAddress, issuedAt, expiresAt, now);
    }

    public RefreshToken markRevokedReuseDetected(Instant now) {
        return new RefreshToken(
                id, tenantId, userId, tokenHash, parentId,
                RefreshTokenStatus.REVOKED_REUSE_DETECTED,
                deviceLabel, ipAddress, issuedAt, expiresAt, now);
    }

    public RefreshToken touch(Instant now) {
        return new RefreshToken(
                id, tenantId, userId, tokenHash, parentId, status,
                deviceLabel, ipAddress, issuedAt, expiresAt, now);
    }

    public boolean isUsable(Instant now) {
        return status == RefreshTokenStatus.ACTIVE && now.isBefore(expiresAt);
    }

    /**
     * 이미 회전된 토큰이 다시 사용된 것 — 탈취 의심 신호.
     */
    public boolean isReuseSignal() {
        return status == RefreshTokenStatus.REVOKED_ROTATED;
    }

    public UUID id() { return id; }
    public TenantId tenantId() { return tenantId; }
    public UserId userId() { return userId; }
    public String tokenHash() { return tokenHash; }
    public UUID parentId() { return parentId; }
    public RefreshTokenStatus status() { return status; }
    public String deviceLabel() { return deviceLabel; }
    public String ipAddress() { return ipAddress; }
    public Instant issuedAt() { return issuedAt; }
    public Instant expiresAt() { return expiresAt; }
    public Instant lastUsedAt() { return lastUsedAt; }

    /** tokenHash 평문은 노출하지 않는 toString. */
    @Override
    public String toString() {
        return "RefreshToken{id=" + id + ", userId=" + userId.asString()
                + ", status=" + status
                + ", expiresAt=" + expiresAt + "}";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshToken other)) return false;
        return Objects.equals(id, other.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
