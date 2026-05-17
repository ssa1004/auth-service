package com.example.auth.adapter.out.persistence.tenant

import com.example.auth.application.port.out.TenantRepository
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.tenant.Tenant
import java.util.Optional
import org.springframework.stereotype.Repository

@Repository
class TenantRepositoryAdapter(
    private val jpa: TenantJpaRepository,
) : TenantRepository {

    override fun save(tenant: Tenant): Tenant = jpa.save(TenantEntity.from(tenant)).toDomain()

    override fun findById(id: TenantId): Optional<Tenant> =
        jpa.findById(id.value).map { it.toDomain() }

    override fun findBySlug(slug: String): Optional<Tenant> =
        jpa.findBySlug(slug).map { it.toDomain() }
}
