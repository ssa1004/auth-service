package com.example.auth.adapter.in.rest;

import jakarta.validation.constraints.NotBlank;

public record VerifyMfaRequest(
        @NotBlank String mfaToken,
        @NotBlank String code,
        String deviceLabel) {
}
