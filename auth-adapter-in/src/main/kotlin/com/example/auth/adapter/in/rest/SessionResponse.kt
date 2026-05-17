package com.example.auth.adapter.`in`.rest

import com.example.auth.application.port.`in`.ListMySessionsUseCase.SessionView
import java.time.Instant
import java.util.UUID

@JvmRecord
data class SessionResponse(
    val sessionId: UUID,
    val deviceLabel: String?,
    val ipAddress: String?,
    val issuedAt: Instant,
    val lastUsedAt: Instant?,
    val expiresAt: Instant,
) {

    companion object {

        @JvmStatic
        fun from(v: SessionView): SessionResponse = SessionResponse(
            v.sessionId,
            v.deviceLabel,
            v.ipAddress,
            v.issuedAt,
            v.lastUsedAt,
            v.expiresAt,
        )
    }
}
