package com.example.auth.application.security;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.role.Permission;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Access JWT 의 표준 + 커스텀 claim 한 묶음.
 *
 * <ul>
 *   <li>{@code sub} = userId</li>
 *   <li>{@code tnt} = tenantId — multi-tenant 격리 (ADR-0006)</li>
 *   <li>{@code roles} = role slug 집합</li>
 *   <li>{@code permissions} = permission name 집합 (consumer 가 추가 lookup 없이 인가 결정)</li>
 *   <li>{@code amr} = "pwd" 또는 ["pwd","mfa"] — RFC 8176</li>
 *   <li>access TTL = 15분</li>
 * </ul>
 */
public record AccessTokenClaims(
        UserId userId,
        TenantId tenantId,
        Set<String> roles,
        Set<String> permissions,
        Set<String> amr,
        Duration ttl) {

    public AccessTokenClaims {
        Objects.requireNonNull(userId);
        Objects.requireNonNull(tenantId);
        Objects.requireNonNull(ttl);
        roles = roles == null ? Set.of() : Set.copyOf(new LinkedHashSet<>(roles));
        permissions = permissions == null ? Set.of() : Set.copyOf(new LinkedHashSet<>(permissions));
        amr = amr == null ? Set.of() : Set.copyOf(new LinkedHashSet<>(amr));
    }

    public static AccessTokenClaims forUser(
            UserId userId,
            TenantId tenantId,
            Set<String> roles,
            Set<Permission> permissions,
            Set<String> amr,
            Duration ttl) {
        Set<String> permNames = new LinkedHashSet<>();
        if (permissions != null) {
            for (Permission p : permissions) permNames.add(p.name());
        }
        return new AccessTokenClaims(userId, tenantId, roles, permNames, amr, ttl);
    }
}
