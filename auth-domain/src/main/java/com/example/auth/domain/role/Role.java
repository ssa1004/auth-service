package com.example.auth.domain.role;

import com.example.auth.domain.common.TenantId;
import jakarta.validation.constraints.NotBlank;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Role — 사용자에게 부여되는 권한 집합. 테넌트 안에서 unique (slug 기준).
 *
 * <p>"admin", "billing-operator", "viewer" 같은 라벨이 들어갑니다. 시스템 기본 role
 * (예: USER) 은 회원가입 시 자동 부여됩니다.
 *
 * <p>주의: Role 자체는 audit / 로그 출력 가능 (PII 아님). 단, 어떤 사용자가 어떤 role 을
 * 받았는지는 audit log 의 별도 이벤트로 추적합니다.
 */
public record Role(
        UUID id,
        TenantId tenantId,
        @NotBlank String slug,
        @NotBlank String displayName,
        Set<Permission> permissions) {

    public Role {
        Objects.requireNonNull(id, "role id 는 null 일 수 없습니다");
        Objects.requireNonNull(tenantId, "tenantId 는 null 일 수 없습니다");
        if (slug == null || slug.isBlank()) {
            throw new IllegalArgumentException("slug 는 비어있을 수 없습니다");
        }
        if (displayName == null || displayName.isBlank()) {
            throw new IllegalArgumentException("displayName 은 비어있을 수 없습니다");
        }
        permissions = permissions == null
                ? Collections.emptySet()
                : Collections.unmodifiableSet(new LinkedHashSet<>(permissions));
    }

    public static Role create(TenantId tenantId, String slug, String displayName, Set<Permission> permissions) {
        return new Role(UUID.randomUUID(), tenantId, slug, displayName, permissions);
    }

    public Role withPermissions(Set<Permission> newPermissions) {
        return new Role(id, tenantId, slug, displayName, newPermissions);
    }

    public boolean hasPermission(Permission permission) {
        return permissions.contains(permission);
    }
}
