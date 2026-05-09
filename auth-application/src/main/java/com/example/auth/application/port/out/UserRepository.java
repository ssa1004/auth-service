package com.example.auth.application.port.out;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.user.User;
import java.util.Optional;

/**
 * User aggregate 저장소 port. tenant 격리는 모든 query 가 강제합니다 (ADR-0006).
 */
public interface UserRepository {

    User save(User user);

    Optional<User> findById(TenantId tenantId, UserId id);

    Optional<User> findByEmail(TenantId tenantId, String email);

    boolean existsByEmail(TenantId tenantId, String email);
}
