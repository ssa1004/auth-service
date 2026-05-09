package com.example.auth.application.port.out;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.role.Role;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RoleRepository {

    Role save(Role role);

    Optional<Role> findById(TenantId tenantId, UUID roleId);

    Optional<Role> findBySlug(TenantId tenantId, String slug);

    List<Role> findByUser(TenantId tenantId, UserId userId);

    void assignToUser(TenantId tenantId, UserId userId, UUID roleId);

    void revokeFromUser(TenantId tenantId, UserId userId, UUID roleId);
}
