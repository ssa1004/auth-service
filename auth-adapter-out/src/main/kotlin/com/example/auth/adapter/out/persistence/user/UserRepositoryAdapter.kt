package com.example.auth.adapter.out.persistence.user

import com.example.auth.application.port.out.UserRepository
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import com.example.auth.domain.user.User
import java.util.Optional
import org.springframework.stereotype.Repository

@Repository
class UserRepositoryAdapter(
    private val jpa: UserJpaRepository,
) : UserRepository {

    override fun save(user: User): User = jpa.save(UserEntity.from(user)).toDomain()

    override fun findById(tenantId: TenantId, id: UserId): Optional<User> =
        jpa.findByIdAndTenantId(id.value, tenantId.value).map { it.toDomain() }

    override fun findByEmail(tenantId: TenantId, email: String): Optional<User> =
        jpa.findByTenantIdAndEmail(tenantId.value, email.lowercase().trim()).map { it.toDomain() }

    override fun existsByEmail(tenantId: TenantId, email: String): Boolean =
        jpa.existsByTenantIdAndEmail(tenantId.value, email.lowercase().trim())
}
