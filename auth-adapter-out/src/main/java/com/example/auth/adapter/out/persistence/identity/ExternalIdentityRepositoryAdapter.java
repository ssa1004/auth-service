package com.example.auth.adapter.out.persistence.identity;

import com.example.auth.application.port.out.ExternalIdentityRepository;
import com.example.auth.domain.identity.ExternalIdentity;
import com.example.auth.domain.identity.ExternalProvider;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class ExternalIdentityRepositoryAdapter implements ExternalIdentityRepository {

    private final ExternalIdentityJpaRepository jpa;

    @Override
    public Optional<ExternalIdentity> findByProviderSubject(
            ExternalProvider provider, String providerUserId) {
        return jpa.findByProviderAndProviderUserId(provider.name(), providerUserId)
                .map(ExternalIdentityEntity::toDomain);
    }

    @Override
    public ExternalIdentity save(ExternalIdentity identity) {
        return jpa.save(ExternalIdentityEntity.from(identity)).toDomain();
    }
}
