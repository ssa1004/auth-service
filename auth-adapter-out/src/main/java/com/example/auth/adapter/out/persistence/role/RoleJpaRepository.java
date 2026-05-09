package com.example.auth.adapter.out.persistence.role;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleJpaRepository extends JpaRepository<RoleEntity, UUID> {

    Optional<RoleEntity> findByIdAndTenantId(UUID id, UUID tenantId);

    Optional<RoleEntity> findByTenantIdAndSlug(UUID tenantId, String slug);
}
