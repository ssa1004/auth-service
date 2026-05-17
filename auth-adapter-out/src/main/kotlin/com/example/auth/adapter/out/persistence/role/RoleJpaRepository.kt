package com.example.auth.adapter.out.persistence.role

import java.util.Optional
import java.util.UUID
import org.springframework.data.jpa.repository.JpaRepository

interface RoleJpaRepository : JpaRepository<RoleEntity, UUID> {

    fun findByIdAndTenantId(id: UUID, tenantId: UUID): Optional<RoleEntity>

    fun findByTenantIdAndSlug(tenantId: UUID, slug: String): Optional<RoleEntity>
}
