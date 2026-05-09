package com.example.auth.adapter.out.persistence.identity;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ExternalIdentityJpaRepository extends JpaRepository<ExternalIdentityEntity, UUID> {

    Optional<ExternalIdentityEntity> findByProviderAndProviderUserId(String provider, String providerUserId);
}
