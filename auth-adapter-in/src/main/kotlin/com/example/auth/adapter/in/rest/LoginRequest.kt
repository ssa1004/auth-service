package com.example.auth.adapter.`in`.rest

import jakarta.validation.constraints.NotBlank

@JvmRecord
data class LoginRequest(
    @field:NotBlank val tenantSlug: String,
    @field:NotBlank val email: String,
    @field:NotBlank val password: String,
    val deviceLabel: String?,
)
