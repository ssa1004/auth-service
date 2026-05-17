package com.example.auth.adapter.out.persistence.mfa

import com.example.auth.application.port.out.MfaSecretRepository
import com.example.auth.domain.common.UserId
import com.example.auth.domain.mfa.MfaSecret
import java.util.Optional
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional

@Repository
class MfaSecretRepositoryAdapter(
    private val jpa: MfaSecretJpaRepository,
) : MfaSecretRepository {

    override fun save(secret: MfaSecret): MfaSecret =
        jpa.save(MfaSecretEntity.from(secret)).toDomain()

    override fun findByUser(userId: UserId): Optional<MfaSecret> =
        jpa.findByUserId(userId.value).map { it.toDomain() }

    @Transactional
    override fun deleteByUser(userId: UserId) {
        jpa.deleteByUserId(userId.value)
    }
}
