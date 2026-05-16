package com.example.auth.application.port.`in`

import com.example.auth.application.security.AuthTokens
import jakarta.validation.constraints.NotBlank

interface RefreshTokenUseCase {

    /**
     * @throws com.example.auth.application.exception.RefreshReuseDetectedException
     *         이미 회전된 token 이 다시 들어옴 — 사용자의 모든 세션이 동시에 강제 revoke 됨.
     */
    fun refresh(cmd: Command): AuthTokens

    @JvmRecord
    data class Command(
        @field:NotBlank val refreshTokenPlain: String,
        val ipAddress: String?,
        val userAgent: String?,
    )
}
