package com.example.auth.adapter.out.persistence.user

import java.util.Optional
import java.util.UUID
import org.springframework.data.jpa.repository.JpaRepository

interface UserJpaRepository : JpaRepository<UserEntity, UUID> {

    fun findByIdAndTenantId(id: UUID, tenantId: UUID): Optional<UserEntity>

    fun findByTenantIdAndEmail(tenantId: UUID, email: String): Optional<UserEntity>

    fun existsByTenantIdAndEmail(tenantId: UUID, email: String): Boolean
}
