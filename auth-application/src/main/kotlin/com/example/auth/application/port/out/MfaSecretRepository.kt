package com.example.auth.application.port.out

import com.example.auth.domain.common.UserId
import com.example.auth.domain.mfa.MfaSecret
import java.util.Optional

interface MfaSecretRepository {

    fun save(secret: MfaSecret): MfaSecret

    fun findByUser(userId: UserId): Optional<MfaSecret>

    fun deleteByUser(userId: UserId)
}
