package com.example.auth.adapter.out.persistence.identity

import com.example.auth.application.port.out.ExternalIdentityRepository
import com.example.auth.domain.identity.ExternalIdentity
import com.example.auth.domain.identity.ExternalProvider
import java.util.Optional
import org.springframework.stereotype.Repository

@Repository
class ExternalIdentityRepositoryAdapter(
    private val jpa: ExternalIdentityJpaRepository,
) : ExternalIdentityRepository {

    override fun findByProviderSubject(
        provider: ExternalProvider,
        providerUserId: String,
    ): Optional<ExternalIdentity> =
        jpa.findByProviderAndProviderUserId(provider.name, providerUserId)
            .map { it.toDomain() }

    override fun save(identity: ExternalIdentity): ExternalIdentity =
        jpa.save(ExternalIdentityEntity.from(identity)).toDomain()
}
