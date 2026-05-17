package com.example.auth.adapter.out.persistence.mfa

import java.util.Optional
import java.util.UUID
import org.springframework.data.jpa.repository.JpaRepository

interface MfaSecretJpaRepository : JpaRepository<MfaSecretEntity, UUID> {

    fun findByUserId(userId: UUID): Optional<MfaSecretEntity>

    fun deleteByUserId(userId: UUID)
}
