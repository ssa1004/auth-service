package com.example.auth.adapter.out.persistence.user

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import com.example.auth.domain.user.MfaStatus
import com.example.auth.domain.user.User
import com.example.auth.domain.user.UserStatus
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import jakarta.persistence.UniqueConstraint
import java.time.Instant
import java.util.UUID

@Entity
@Table(
    name = "users",
    uniqueConstraints = [
        UniqueConstraint(name = "users_tenant_email_uq", columnNames = ["tenant_id", "email"]),
    ],
)
class UserEntity {

    @Id
    private var id: UUID = UUID(0, 0)

    @Column(name = "tenant_id", nullable = false)
    private var tenantId: UUID = UUID(0, 0)

    @Column(nullable = false)
    private var email: String = ""

    @Column(name = "password_hash", nullable = false)
    private var passwordHash: String = ""

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private var status: UserStatus = UserStatus.PENDING_VERIFICATION

    @Enumerated(EnumType.STRING)
    @Column(name = "mfa_status", nullable = false)
    private var mfaStatus: MfaStatus = MfaStatus.DISABLED

    @Column(name = "created_at", nullable = false)
    private var createdAt: Instant = Instant.EPOCH

    @Column(name = "updated_at", nullable = false)
    private var updatedAt: Instant = Instant.EPOCH

    fun getId(): UUID = id

    fun toDomain(): User = User(
        UserId.of(id), TenantId.of(tenantId), email, passwordHash,
        status, mfaStatus, createdAt, updatedAt,
    )

    companion object {
        @JvmStatic
        fun from(u: User): UserEntity = UserEntity().apply {
            id = u.id.value
            tenantId = u.tenantId.value
            email = u.email
            passwordHash = u.passwordHash
            status = u.status
            mfaStatus = u.mfaStatus
            createdAt = u.createdAt
            updatedAt = u.updatedAt
        }
    }
}
