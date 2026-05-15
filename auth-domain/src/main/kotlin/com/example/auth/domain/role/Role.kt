package com.example.auth.domain.role

import com.example.auth.domain.common.TenantId
import jakarta.validation.constraints.NotBlank
import java.util.Collections
import java.util.LinkedHashSet
import java.util.UUID

/**
 * Role — 사용자에게 부여되는 권한 집합. 테넌트 안에서 unique (slug 기준).
 *
 * "admin", "billing-operator", "viewer" 같은 라벨이 들어갑니다. 시스템 기본 role
 * (예: USER) 은 회원가입 시 자동 부여됩니다.
 *
 * 주의: Role 자체는 audit / 로그 출력 가능 (PII 아님). 단, 어떤 사용자가 어떤 role 을
 * 받았는지는 audit log 의 별도 이벤트로 추적합니다.
 *
 * `@JvmRecord data class` — Java 호출자 (`r.id()` / `r.slug()` / `r.permissions()`
 * record-style accessor) 그대로 동작.
 */
@JvmRecord
data class Role(
    val id: UUID,
    val tenantId: TenantId,
    @field:NotBlank val slug: String,
    @field:NotBlank val displayName: String,
    val permissions: Set<Permission>,
) {

    init {
        require(slug.isNotBlank()) { "slug 는 비어있을 수 없습니다" }
        require(displayName.isNotBlank()) { "displayName 은 비어있을 수 없습니다" }
    }

    fun withPermissions(newPermissions: Set<Permission>?): Role =
        Role(id, tenantId, slug, displayName, normalizePermissions(newPermissions))

    fun hasPermission(permission: Permission): Boolean = permissions.contains(permission)

    companion object {
        @JvmStatic
        fun create(
            tenantId: TenantId,
            slug: String,
            displayName: String,
            permissions: Set<Permission>?,
        ): Role = Role(
            UUID.randomUUID(),
            tenantId,
            slug,
            displayName,
            // Java compact constructor 의 방어적 복사 (삽입순서 보존 + 불변) 를 factory 에서 수행.
            normalizePermissions(permissions),
        )

        /** null → 빈 set, 그 외엔 삽입순서 보존 불변 복사본. */
        @JvmStatic
        private fun normalizePermissions(permissions: Set<Permission>?): Set<Permission> =
            if (permissions == null) emptySet()
            else Collections.unmodifiableSet(LinkedHashSet(permissions))
    }
}
