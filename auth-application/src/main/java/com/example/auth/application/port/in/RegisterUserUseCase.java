package com.example.auth.application.port.in;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public interface RegisterUserUseCase {

    UserId register(Command cmd);

    record Command(
            @NotBlank String tenantSlug,
            @NotBlank @Email String email,
            @NotBlank @Size(min = 12, max = 128) String rawPassword) {

        // 정책: 최소 12자. 별도 복잡도 요구는 두지 않음 (NIST SP 800-63B 권고).
    }
}
