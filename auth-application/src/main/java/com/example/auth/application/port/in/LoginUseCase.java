package com.example.auth.application.port.in;

import com.example.auth.application.security.AuthTokens;
import jakarta.validation.constraints.NotBlank;

public interface LoginUseCase {

    /**
     * @return access + refresh 한 묶음.
     * @throws com.example.auth.application.exception.MfaRequiredException MFA 활성 사용자
     * @throws com.example.auth.application.exception.InvalidCredentialsException 그 외 모든 실패 (사용자 미존재 / 잠김 / 비밀번호 불일치)
     * @throws com.example.auth.application.exception.RateLimitedException brute-force 의심
     */
    AuthTokens login(Command cmd);

    record Command(
            @NotBlank String tenantSlug,
            @NotBlank String email,
            @NotBlank String rawPassword,
            String ipAddress,
            String userAgent,
            String deviceLabel) {
    }
}
