package com.example.auth.domain.tenant

import com.example.auth.domain.common.TenantId
import jakarta.validation.constraints.NotBlank
import java.time.Instant

/**
 * 테넌트 — multi-tenant 격리 단위. 한 테넌트 안의 사용자/role/refresh 토큰은 서로 보이지만,
 * 다른 테넌트와는 완전 분리됩니다.
 *
 * 격리 전략은 ADR-0006 — 본 도메인은 RBAC 가 적용되는 모든 query 에 tenant filter 를
 * 강제 (PG RLS 가 아니라 application 레벨). slug 는 사람이 읽는 식별자, id 는 안정 키.
 *
 * `@JvmRecord data class` — Java 호출자 (`t.id()` / `t.slug()` / `t.status()`
 * record-style accessor) 그대로 동작.
 */
@JvmRecord
data class Tenant(
    val id: TenantId,
    @field:NotBlank val slug: String,
    @field:NotBlank val displayName: String,
    val status: TenantStatus,
    val createdAt: Instant,
) {

    init {
        require(slug.isNotBlank()) { "slug 는 비어있을 수 없습니다" }
        require(displayName.isNotBlank()) { "displayName 은 비어있을 수 없습니다" }
    }

    fun isActive(): Boolean = status == TenantStatus.ACTIVE

    companion object {
        @JvmStatic
        fun create(slug: String, displayName: String, now: Instant): Tenant =
            Tenant(TenantId.newId(), slug, displayName, TenantStatus.ACTIVE, now)
    }
}
