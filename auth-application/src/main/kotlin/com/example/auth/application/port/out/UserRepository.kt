package com.example.auth.application.port.out

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import com.example.auth.domain.user.User
import java.util.Optional

/**
 * User aggregate 저장소 port. tenant 격리는 모든 query 가 강제합니다 (ADR-0006).
 */
interface UserRepository {

    fun save(user: User): User

    fun findById(tenantId: TenantId, id: UserId): Optional<User>

    fun findByEmail(tenantId: TenantId, email: String): Optional<User>

    fun existsByEmail(tenantId: TenantId, email: String): Boolean
}
