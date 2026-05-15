package com.example.auth.domain.token

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import java.time.Duration
import java.time.Instant
import java.util.Objects
import java.util.UUID

/**
 * Refresh token aggregate.
 *
 * 핵심 규칙:
 * - 도메인 객체에는 token 평문이 들어오지 않습니다 — `tokenHash` 만 보관 (SHA-256).
 *   탈취 가정 하에 DB 가 새 나가도 직접 사용 불가능.
 * - 한 토큰은 한 번만 사용 가능 (rotation). 사용되면 `REVOKED_ROTATED` 가 되고
 *   새 토큰의 `parentId` 로 연결됩니다.
 * - 이미 회전된 토큰이 다시 들어오면 reuse 신호로 간주하여 사용자의 모든 토큰을
 *   강제 revoke. (도메인은 상태 천이 책임만, 일괄 revoke 는 application 의 책임)
 *
 * 불변 객체이며 상태 천이는 새 인스턴스를 반환한다. id 기준 동일성 + tokenHash 를
 * 노출하지 않는 toString 을 위해 일반 class 로 두고 `@get:JvmName` 으로 Java record-style
 * accessor (`rt.id()` 등) 호환을 유지한다.
 */
class RefreshToken(
    @get:JvmName("id") val id: UUID,
    @get:JvmName("tenantId") val tenantId: TenantId,
    @get:JvmName("userId") val userId: UserId,
    @get:JvmName("tokenHash") val tokenHash: String,
    @get:JvmName("parentId") val parentId: UUID?,
    @get:JvmName("status") val status: RefreshTokenStatus,
    @get:JvmName("deviceLabel") val deviceLabel: String?,
    @get:JvmName("ipAddress") val ipAddress: String?,
    @get:JvmName("issuedAt") val issuedAt: Instant,
    @get:JvmName("expiresAt") val expiresAt: Instant,
    @get:JvmName("lastUsedAt") val lastUsedAt: Instant?,
) {

    init {
        require(tokenHash.length >= 32) {
            "tokenHash 는 hash 결과 (>= 32자) 여야 합니다 — 평문 token 금지"
        }
        require(expiresAt.isAfter(issuedAt)) { "expiresAt 은 issuedAt 보다 미래여야 합니다" }
    }

    fun markRotated(now: Instant): RefreshToken = RefreshToken(
        id, tenantId, userId, tokenHash, parentId,
        RefreshTokenStatus.REVOKED_ROTATED,
        deviceLabel, ipAddress, issuedAt, expiresAt, now,
    )

    fun markRevokedByUser(now: Instant): RefreshToken = RefreshToken(
        id, tenantId, userId, tokenHash, parentId,
        RefreshTokenStatus.REVOKED_BY_USER,
        deviceLabel, ipAddress, issuedAt, expiresAt, now,
    )

    /** 운영자가 RFC 7009 revoke 로 강제 종료. */
    fun markRevokedByAdmin(now: Instant): RefreshToken = RefreshToken(
        id, tenantId, userId, tokenHash, parentId,
        RefreshTokenStatus.REVOKED_BY_ADMIN,
        deviceLabel, ipAddress, issuedAt, expiresAt, now,
    )

    fun markRevokedReuseDetected(now: Instant): RefreshToken = RefreshToken(
        id, tenantId, userId, tokenHash, parentId,
        RefreshTokenStatus.REVOKED_REUSE_DETECTED,
        deviceLabel, ipAddress, issuedAt, expiresAt, now,
    )

    fun touch(now: Instant): RefreshToken = RefreshToken(
        id, tenantId, userId, tokenHash, parentId, status,
        deviceLabel, ipAddress, issuedAt, expiresAt, now,
    )

    fun isUsable(now: Instant): Boolean =
        status == RefreshTokenStatus.ACTIVE && now.isBefore(expiresAt)

    /**
     * 이미 회전된 토큰이 다시 사용된 것 — 탈취 의심 신호.
     */
    fun isReuseSignal(): Boolean = status == RefreshTokenStatus.REVOKED_ROTATED

    /**
     * 회전 직후 짧은 시간 안의 정당한 모바일 retry 인지 판단.
     *
     * **왜 필요**: 모바일 client 의 네트워크 jitter / 백그라운드 retry 로 같은 refresh
     * 가 이미 회전된 직후 한 번 더 들어올 수 있습니다. 이걸 무조건 reuse 로 간주하면 정상
     * 사용자가 자신의 모든 세션을 잃는 사고가 됩니다. 짧은 grace window 안 retry 는 조용한
     * 401 로 처리하고 사용자가 새 refresh 로 재시도하게 둡니다.
     *
     * grace window 밖이거나 IP 가 다른 retry 는 진짜 탈취 의심으로 간주하여 일괄 revoke
     * 합니다 (ADR-0015).
     *
     * @param now             현재 시각
     * @param graceWindow     grace 윈도우 (예: 5s)
     * @param sameNetwork     호출자 측에서 판단한 같은 IP / userAgent 여부
     * @return true = grace 에 해당 (revoke 하지 않음), false = 진짜 reuse
     */
    fun isWithinReuseGrace(now: Instant, graceWindow: Duration, sameNetwork: Boolean): Boolean {
        if (status != RefreshTokenStatus.REVOKED_ROTATED) return false
        if (lastUsedAt == null) return false
        if (!sameNetwork) return false
        val sinceRotation = Duration.between(lastUsedAt, now)
        return !sinceRotation.isNegative && sinceRotation <= graceWindow
    }

    /** tokenHash 평문은 노출하지 않는 toString. */
    override fun toString(): String =
        "RefreshToken{id=$id, userId=${userId.asString()}, status=$status, expiresAt=$expiresAt}"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RefreshToken) return false
        return id == other.id
    }

    override fun hashCode(): Int = Objects.hash(id)

    companion object {
        @JvmStatic
        fun issue(
            tenantId: TenantId,
            userId: UserId,
            tokenHash: String,
            parentId: UUID?,
            deviceLabel: String?,
            ipAddress: String?,
            issuedAt: Instant,
            expiresAt: Instant,
        ): RefreshToken = RefreshToken(
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
            null,
        )
    }
}
