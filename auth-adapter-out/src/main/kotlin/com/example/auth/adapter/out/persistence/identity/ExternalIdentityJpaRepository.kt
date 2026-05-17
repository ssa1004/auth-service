package com.example.auth.adapter.out.persistence.identity

import java.util.Optional
import java.util.UUID
import org.springframework.data.jpa.repository.JpaRepository

interface ExternalIdentityJpaRepository : JpaRepository<ExternalIdentityEntity, UUID> {

    fun findByProviderAndProviderUserId(provider: String, providerUserId: String): Optional<ExternalIdentityEntity>
}
