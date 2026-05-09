package com.example.auth.application.port.out;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.tenant.Tenant;
import java.util.Optional;

public interface TenantRepository {

    Tenant save(Tenant tenant);

    Optional<Tenant> findById(TenantId id);

    Optional<Tenant> findBySlug(String slug);
}
