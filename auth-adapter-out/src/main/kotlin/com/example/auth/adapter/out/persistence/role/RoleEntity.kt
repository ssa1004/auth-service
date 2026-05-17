package com.example.auth.adapter.out.persistence.role

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.role.Permission
import com.example.auth.domain.role.Role
import jakarta.persistence.CollectionTable
import jakarta.persistence.Column
import jakarta.persistence.ElementCollection
import jakarta.persistence.Entity
import jakarta.persistence.FetchType
import jakarta.persistence.Id
import jakarta.persistence.JoinColumn
import jakarta.persistence.Table
import jakarta.persistence.UniqueConstraint
import java.util.LinkedHashSet
import java.util.UUID

@Entity
@Table(
    name = "roles",
    uniqueConstraints = [
        UniqueConstraint(name = "roles_tenant_slug_uq", columnNames = ["tenant_id", "slug"]),
    ],
)
class RoleEntity {

    @Id
    private var id: UUID = UUID(0, 0)

    @Column(name = "tenant_id", nullable = false)
    private var tenantId: UUID = UUID(0, 0)

    @Column(nullable = false)
    private var slug: String = ""

    @Column(name = "display_name", nullable = false)
    private var displayName: String = ""

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "role_permissions", joinColumns = [JoinColumn(name = "role_id")])
    @Column(name = "permission", nullable = false)
    private var permissions: MutableSet<String> = HashSet()

    fun getId(): UUID = id
    fun getTenantId(): UUID = tenantId

    fun toDomain(): Role {
        val perms: Set<Permission> = permissions.mapTo(LinkedHashSet()) { Permission.of(it) }
        return Role(id, TenantId.of(tenantId), slug, displayName, perms)
    }

    companion object {
        @JvmStatic
        fun from(r: Role): RoleEntity = RoleEntity().apply {
            id = r.id
            tenantId = r.tenantId.value
            slug = r.slug
            displayName = r.displayName
            permissions = r.permissions.mapTo(LinkedHashSet()) { it.name }
        }
    }
}
