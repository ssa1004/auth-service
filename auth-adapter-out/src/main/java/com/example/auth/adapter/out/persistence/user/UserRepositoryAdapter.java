package com.example.auth.adapter.out.persistence.user;

import com.example.auth.application.port.out.UserRepository;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.user.User;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class UserRepositoryAdapter implements UserRepository {

    private final UserJpaRepository jpa;

    @Override
    public User save(User user) {
        return jpa.save(UserEntity.from(user)).toDomain();
    }

    @Override
    public Optional<User> findById(TenantId tenantId, UserId id) {
        return jpa.findByIdAndTenantId(id.value(), tenantId.value()).map(UserEntity::toDomain);
    }

    @Override
    public Optional<User> findByEmail(TenantId tenantId, String email) {
        return jpa.findByTenantIdAndEmail(tenantId.value(), email.toLowerCase().trim())
                .map(UserEntity::toDomain);
    }

    @Override
    public boolean existsByEmail(TenantId tenantId, String email) {
        return jpa.existsByTenantIdAndEmail(tenantId.value(), email.toLowerCase().trim());
    }
}
