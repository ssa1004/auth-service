package com.example.auth.adapter.out.persistence.role

import com.example.auth.application.port.out.RoleRepository
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import com.example.auth.domain.role.Role
import java.util.Optional
import java.util.UUID
import org.springframework.stereotype.Repository

@Repository
class RoleRepositoryAdapter(
    private val roleJpa: RoleJpaRepository,
    private val userRoleJpa: UserRoleJpaRepository,
) : RoleRepository {

    override fun save(role: Role): Role = roleJpa.save(RoleEntity.from(role)).toDomain()

    override fun findById(tenantId: TenantId, roleId: UUID): Optional<Role> =
        roleJpa.findByIdAndTenantId(roleId, tenantId.value).map { it.toDomain() }

    override fun findBySlug(tenantId: TenantId, slug: String): Optional<Role> =
        roleJpa.findByTenantIdAndSlug(tenantId.value, slug).map { it.toDomain() }

    override fun findByUser(tenantId: TenantId, userId: UserId): List<Role> {
        val roleIds = userRoleJpa.findRoleIdsByUserId(userId.value)
        if (roleIds.isEmpty()) return emptyList()
        return roleJpa.findAllById(roleIds)
            .filter { it.getTenantId() == tenantId.value }
            .map { it.toDomain() }
    }

    override fun assignToUser(tenantId: TenantId, userId: UserId, roleId: UUID) {
        // tenant 일관성 — role 이 다른 테넌트 소속이면 부여 거절.
        roleJpa.findByIdAndTenantId(roleId, tenantId.value)
            .orElseThrow { IllegalArgumentException("role 이 테넌트와 일치하지 않습니다: $roleId") }
        userRoleJpa.save(UserRoleEntity(userId.value, roleId))
    }

    override fun revokeFromUser(tenantId: TenantId, userId: UserId, roleId: UUID) {
        userRoleJpa.deleteById_UserIdAndId_RoleId(userId.value, roleId)
    }
}
