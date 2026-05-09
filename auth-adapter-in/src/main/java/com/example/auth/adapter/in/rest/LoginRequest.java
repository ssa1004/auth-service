package com.example.auth.adapter.in.rest;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank String tenantSlug,
        @NotBlank String email,
        @NotBlank String password,
        String deviceLabel) {
}
