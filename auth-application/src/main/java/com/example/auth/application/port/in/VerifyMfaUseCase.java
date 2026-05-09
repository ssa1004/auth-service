package com.example.auth.application.port.in;

import com.example.auth.application.security.AuthTokens;
import jakarta.validation.constraints.NotBlank;

public interface VerifyMfaUseCase {

    AuthTokens verify(Command cmd);

    record Command(
            @NotBlank String mfaChallengeToken,
            @NotBlank String code,
            String ipAddress,
            String userAgent,
            String deviceLabel) {
    }
}
