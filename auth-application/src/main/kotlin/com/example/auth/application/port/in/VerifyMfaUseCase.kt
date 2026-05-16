package com.example.auth.application.port.`in`

import com.example.auth.application.security.AuthTokens
import jakarta.validation.constraints.NotBlank

interface VerifyMfaUseCase {

    fun verify(cmd: Command): AuthTokens

    @JvmRecord
    data class Command(
        @field:NotBlank val mfaChallengeToken: String,
        @field:NotBlank val code: String,
        val ipAddress: String?,
        val userAgent: String?,
        val deviceLabel: String?,
    )
}
