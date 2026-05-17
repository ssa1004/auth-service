package com.example.auth.adapter.out.persistence.tenant

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.tenant.Tenant
import com.example.auth.domain.tenant.TenantStatus
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "tenants")
class TenantEntity {

    @Id
    private var id: UUID = UUID(0, 0)

    @Column(nullable = false, unique = true)
    private var slug: String = ""

    @Column(name = "display_name", nullable = false)
    private var displayName: String = ""

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private var status: TenantStatus = TenantStatus.ACTIVE

    @Column(name = "created_at", nullable = false)
    private var createdAt: Instant = Instant.EPOCH

    fun toDomain(): Tenant = Tenant(TenantId.of(id), slug, displayName, status, createdAt)

    companion object {
        @JvmStatic
        fun from(t: Tenant): TenantEntity = TenantEntity().apply {
            id = t.id.value
            slug = t.slug
            displayName = t.displayName
            status = t.status
            createdAt = t.createdAt
        }
    }
}
