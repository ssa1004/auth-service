package com.example.auth.adapter.out.persistence.role;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.role.Permission;
import com.example.auth.domain.role.Role;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Entity
@Table(name = "roles", uniqueConstraints = @UniqueConstraint(
        name = "roles_tenant_slug_uq", columnNames = {"tenant_id", "slug"}))
public class RoleEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(nullable = false)
    private String slug;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "role_permissions", joinColumns = @JoinColumn(name = "role_id"))
    @Column(name = "permission", nullable = false)
    private Set<String> permissions = new HashSet<>();

    protected RoleEntity() {}

    public static RoleEntity from(Role r) {
        RoleEntity e = new RoleEntity();
        e.id = r.id();
        e.tenantId = r.tenantId().value();
        e.slug = r.slug();
        e.displayName = r.displayName();
        e.permissions = r.permissions().stream().map(Permission::name)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return e;
    }

    public Role toDomain() {
        Set<Permission> perms = permissions.stream().map(Permission::of)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return new Role(id, TenantId.of(tenantId), slug, displayName, perms);
    }

    public UUID getId() { return id; }
    public UUID getTenantId() { return tenantId; }
}
