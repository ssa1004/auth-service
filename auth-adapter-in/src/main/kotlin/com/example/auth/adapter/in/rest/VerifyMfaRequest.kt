package com.example.auth.adapter.`in`.rest

import jakarta.validation.constraints.NotBlank

@JvmRecord
data class VerifyMfaRequest(
    @field:NotBlank val mfaToken: String,
    @field:NotBlank val code: String,
    val deviceLabel: String?,
)
