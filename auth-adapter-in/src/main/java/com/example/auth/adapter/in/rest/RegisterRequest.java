package com.example.auth.adapter.in.rest;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank String tenantSlug,
        @NotBlank @Email String email,
        @NotBlank @Size(min = 12, max = 128) String password,
        String deviceLabel) {
}
