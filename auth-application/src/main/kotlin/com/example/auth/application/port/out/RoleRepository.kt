package com.example.auth.application.port.out

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import com.example.auth.domain.role.Role
import java.util.Optional
import java.util.UUID

interface RoleRepository {

    fun save(role: Role): Role

    fun findById(tenantId: TenantId, roleId: UUID): Optional<Role>

    fun findBySlug(tenantId: TenantId, slug: String): Optional<Role>

    fun findByUser(tenantId: TenantId, userId: UserId): List<Role>

    fun assignToUser(tenantId: TenantId, userId: UserId, roleId: UUID)

    fun revokeFromUser(tenantId: TenantId, userId: UserId, roleId: UUID)
}
