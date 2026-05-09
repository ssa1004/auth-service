package com.example.auth.adapter.out.persistence.role;

import com.example.auth.application.port.out.RoleRepository;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.role.Role;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class RoleRepositoryAdapter implements RoleRepository {

    private final RoleJpaRepository roleJpa;
    private final UserRoleJpaRepository userRoleJpa;

    @Override
    public Role save(Role role) {
        return roleJpa.save(RoleEntity.from(role)).toDomain();
    }

    @Override
    public Optional<Role> findById(TenantId tenantId, UUID roleId) {
        return roleJpa.findByIdAndTenantId(roleId, tenantId.value()).map(RoleEntity::toDomain);
    }

    @Override
    public Optional<Role> findBySlug(TenantId tenantId, String slug) {
        return roleJpa.findByTenantIdAndSlug(tenantId.value(), slug).map(RoleEntity::toDomain);
    }

    @Override
    public List<Role> findByUser(TenantId tenantId, UserId userId) {
        List<UUID> roleIds = userRoleJpa.findRoleIdsByUserId(userId.value());
        if (roleIds.isEmpty()) return List.of();
        return roleJpa.findAllById(roleIds).stream()
                .filter(r -> r.getTenantId().equals(tenantId.value()))
                .map(RoleEntity::toDomain)
                .toList();
    }

    @Override
    public void assignToUser(TenantId tenantId, UserId userId, UUID roleId) {
        // tenant 일관성 — role 이 다른 테넌트 소속이면 부여 거절.
        roleJpa.findByIdAndTenantId(roleId, tenantId.value())
                .orElseThrow(() -> new IllegalArgumentException(
                        "role 이 테넌트와 일치하지 않습니다: " + roleId));
        userRoleJpa.save(new UserRoleEntity(userId.value(), roleId));
    }

    @Override
    public void revokeFromUser(TenantId tenantId, UserId userId, UUID roleId) {
        userRoleJpa.deleteById_UserIdAndId_RoleId(userId.value(), roleId);
    }
}
