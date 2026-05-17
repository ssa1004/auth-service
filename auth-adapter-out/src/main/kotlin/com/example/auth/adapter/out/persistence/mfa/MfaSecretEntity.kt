package com.example.auth.adapter.out.persistence.mfa

import com.example.auth.domain.common.UserId
import com.example.auth.domain.mfa.MfaMethod
import com.example.auth.domain.mfa.MfaSecret
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "mfa_secrets")
class MfaSecretEntity {

    @Id
    private var id: UUID = UUID(0, 0)

    @Column(name = "user_id", nullable = false, unique = true)
    private var userId: UUID = UUID(0, 0)

    @Column(name = "secret_cipher", nullable = false)
    private var secretCipher: String = ""

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private var method: MfaMethod = MfaMethod.TOTP

    @Column(name = "created_at", nullable = false)
    private var createdAt: Instant = Instant.EPOCH

    @Column(name = "confirmed_at")
    private var confirmedAt: Instant? = null

    fun toDomain(): MfaSecret =
        MfaSecret(id, UserId.of(userId), secretCipher, method, createdAt, confirmedAt)

    companion object {
        @JvmStatic
        fun from(s: MfaSecret): MfaSecretEntity = MfaSecretEntity().apply {
            id = s.id
            userId = s.userId.value
            secretCipher = s.secretCipher
            method = s.method
            createdAt = s.createdAt
            confirmedAt = s.confirmedAt
        }
    }
}
