package com.example.auth.adapter.out.persistence.mfa;

import com.example.auth.application.port.out.MfaSecretRepository;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.mfa.MfaSecret;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@RequiredArgsConstructor
public class MfaSecretRepositoryAdapter implements MfaSecretRepository {

    private final MfaSecretJpaRepository jpa;

    @Override
    public MfaSecret save(MfaSecret secret) {
        return jpa.save(MfaSecretEntity.from(secret)).toDomain();
    }

    @Override
    public Optional<MfaSecret> findByUser(UserId userId) {
        return jpa.findByUserId(userId.value()).map(MfaSecretEntity::toDomain);
    }

    @Override
    @Transactional
    public void deleteByUser(UserId userId) {
        jpa.deleteByUserId(userId.value());
    }
}
