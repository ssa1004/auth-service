package com.example.auth.adapter.out.persistence.user;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserJpaRepository extends JpaRepository<UserEntity, UUID> {

    Optional<UserEntity> findByIdAndTenantId(UUID id, UUID tenantId);

    Optional<UserEntity> findByTenantIdAndEmail(UUID tenantId, String email);

    boolean existsByTenantIdAndEmail(UUID tenantId, String email);
}
