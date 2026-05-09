package com.example.auth.adapter.out.persistence.tenant;

import com.example.auth.application.port.out.TenantRepository;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.tenant.Tenant;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class TenantRepositoryAdapter implements TenantRepository {

    private final TenantJpaRepository jpa;

    @Override
    public Tenant save(Tenant tenant) {
        return jpa.save(TenantEntity.from(tenant)).toDomain();
    }

    @Override
    public Optional<Tenant> findById(TenantId id) {
        return jpa.findById(id.value()).map(TenantEntity::toDomain);
    }

    @Override
    public Optional<Tenant> findBySlug(String slug) {
        return jpa.findBySlug(slug).map(TenantEntity::toDomain);
    }
}
