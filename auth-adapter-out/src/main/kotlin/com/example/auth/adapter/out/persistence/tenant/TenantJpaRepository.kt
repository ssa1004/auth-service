package com.example.auth.adapter.out.persistence.tenant

import java.util.Optional
import java.util.UUID
import org.springframework.data.jpa.repository.JpaRepository

interface TenantJpaRepository : JpaRepository<TenantEntity, UUID> {

    fun findBySlug(slug: String): Optional<TenantEntity>
}
