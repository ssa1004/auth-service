package com.example.auth.adapter.out.persistence.mfa;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MfaSecretJpaRepository extends JpaRepository<MfaSecretEntity, UUID> {

    Optional<MfaSecretEntity> findByUserId(UUID userId);

    void deleteByUserId(UUID userId);
}
