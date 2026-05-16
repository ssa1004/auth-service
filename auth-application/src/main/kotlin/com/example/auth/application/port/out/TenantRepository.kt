package com.example.auth.application.port.out

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.tenant.Tenant
import java.util.Optional

interface TenantRepository {

    fun save(tenant: Tenant): Tenant

    fun findById(id: TenantId): Optional<Tenant>

    fun findBySlug(slug: String): Optional<Tenant>
}
