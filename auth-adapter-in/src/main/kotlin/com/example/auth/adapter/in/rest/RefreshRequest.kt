package com.example.auth.adapter.`in`.rest

import jakarta.validation.constraints.NotBlank

@JvmRecord
data class RefreshRequest(
    @field:NotBlank val refreshToken: String,
)
