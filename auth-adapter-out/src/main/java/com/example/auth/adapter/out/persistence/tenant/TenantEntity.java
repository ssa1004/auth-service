package com.example.auth.adapter.out.persistence.tenant;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.tenant.TenantStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "tenants")
public class TenantEntity {

    @Id
    private UUID id;

    @Column(nullable = false, unique = true)
    private String slug;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TenantStatus status;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected TenantEntity() {}

    public static TenantEntity from(Tenant t) {
        TenantEntity e = new TenantEntity();
        e.id = t.id().value();
        e.slug = t.slug();
        e.displayName = t.displayName();
        e.status = t.status();
        e.createdAt = t.createdAt();
        return e;
    }

    public Tenant toDomain() {
        return new Tenant(TenantId.of(id), slug, displayName, status, createdAt);
    }
}
