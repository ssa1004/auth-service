package com.example.auth.application.security

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import com.example.auth.domain.role.Permission
import java.time.Duration
import java.util.LinkedHashSet

/**
 * Access JWT 의 표준 + 커스텀 claim 한 묶음.
 *
 * - `sub` = userId
 * - `tnt` = tenantId — multi-tenant 격리 (ADR-0006)
 * - `roles` = role slug 집합
 * - `permissions` = permission name 집합 (consumer 가 추가 lookup 없이 인가 결정)
 * - `amr` = "pwd" 또는 ["pwd","mfa"] — RFC 8176
 * - access TTL = 15분
 *
 * 방어적 복사 + 정규화가 있어 일반 `class` + `@get:JvmName` 으로 record-style accessor 호환.
 */
class AccessTokenClaims(
    userId: UserId,
    tenantId: TenantId,
    roles: Set<String>?,
    permissions: Set<String>?,
    amr: Set<String>?,
    ttl: Duration,
) {
    @get:JvmName("userId")
    val userId: UserId = userId

    @get:JvmName("tenantId")
    val tenantId: TenantId = tenantId

    @get:JvmName("roles")
    val roles: Set<String> =
        if (roles == null) emptySet() else java.util.Set.copyOf(LinkedHashSet(roles))

    @get:JvmName("permissions")
    val permissions: Set<String> =
        if (permissions == null) emptySet() else java.util.Set.copyOf(LinkedHashSet(permissions))

    @get:JvmName("amr")
    val amr: Set<String> =
        if (amr == null) emptySet() else java.util.Set.copyOf(LinkedHashSet(amr))

    @get:JvmName("ttl")
    val ttl: Duration = ttl

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AccessTokenClaims) return false
        return userId == other.userId &&
            tenantId == other.tenantId &&
            roles == other.roles &&
            permissions == other.permissions &&
            amr == other.amr &&
            ttl == other.ttl
    }

    override fun hashCode(): Int {
        var result = userId.hashCode()
        result = 31 * result + tenantId.hashCode()
        result = 31 * result + roles.hashCode()
        result = 31 * result + permissions.hashCode()
        result = 31 * result + amr.hashCode()
        result = 31 * result + ttl.hashCode()
        return result
    }

    override fun toString(): String =
        "AccessTokenClaims[userId=$userId, tenantId=$tenantId, roles=$roles, " +
            "permissions=$permissions, amr=$amr, ttl=$ttl]"

    companion object {
        @JvmStatic
        fun forUser(
            userId: UserId,
            tenantId: TenantId,
            roles: Set<String>?,
            permissions: Set<Permission>?,
            amr: Set<String>?,
            ttl: Duration,
        ): AccessTokenClaims {
            val permNames = LinkedHashSet<String>()
            permissions?.forEach { permNames.add(it.name) }
            return AccessTokenClaims(userId, tenantId, roles, permNames, amr, ttl)
        }
    }
}
