package com.example.auth.application.port.`in`

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import java.util.UUID

interface RevokeSessionUseCase {

    fun revoke(cmd: Command)

    @JvmRecord
    data class Command(
        val tenantId: TenantId,
        val userId: UserId,
        val sessionId: UUID,
        val ipAddress: String?,
    )
}
