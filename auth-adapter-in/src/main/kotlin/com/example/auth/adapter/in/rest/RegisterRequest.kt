package com.example.auth.adapter.`in`.rest

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

@JvmRecord
data class RegisterRequest(
    @field:NotBlank val tenantSlug: String,
    @field:NotBlank @field:Email val email: String,
    @field:NotBlank @field:Size(min = 12, max = 128) val password: String,
    val deviceLabel: String?,
)
