package com.example.auth.domain.tenant;

import com.example.auth.domain.common.TenantId;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.Objects;

/**
 * 테넌트 — multi-tenant 격리 단위. 한 테넌트 안의 사용자/role/refresh 토큰은 서로 보이지만,
 * 다른 테넌트와는 완전 분리됩니다.
 *
 * <p>격리 전략은 ADR-0006 — 본 도메인은 RBAC 가 적용되는 모든 query 에 tenant filter 를
 * 강제 (PG RLS 가 아니라 application 레벨). slug 는 사람이 읽는 식별자, id 는 안정 키.
 */
public record Tenant(
        TenantId id,
        @NotBlank String slug,
        @NotBlank String displayName,
        TenantStatus status,
        Instant createdAt) {

    public Tenant {
        Objects.requireNonNull(id, "tenant id 는 null 이 될 수 없습니다");
        Objects.requireNonNull(status, "tenant status 는 null 이 될 수 없습니다");
        Objects.requireNonNull(createdAt, "createdAt 은 null 이 될 수 없습니다");
        if (slug == null || slug.isBlank()) {
            throw new IllegalArgumentException("slug 는 비어있을 수 없습니다");
        }
        if (displayName == null || displayName.isBlank()) {
            throw new IllegalArgumentException("displayName 은 비어있을 수 없습니다");
        }
    }

    public static Tenant create(String slug, String displayName, Instant now) {
        return new Tenant(TenantId.newId(), slug, displayName, TenantStatus.ACTIVE, now);
    }

    public boolean isActive() {
        return status == TenantStatus.ACTIVE;
    }
}
