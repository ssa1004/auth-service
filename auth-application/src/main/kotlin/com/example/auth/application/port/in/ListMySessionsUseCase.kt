package com.example.auth.application.port.`in`

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import java.time.Instant
import java.util.UUID

interface ListMySessionsUseCase {

    fun list(tenantId: TenantId, userId: UserId): List<SessionView>

    @JvmRecord
    data class SessionView(
        val sessionId: UUID,
        val deviceLabel: String?,
        val ipAddress: String?,
        val issuedAt: Instant,
        val lastUsedAt: Instant?,
        val expiresAt: Instant,
    )
}
