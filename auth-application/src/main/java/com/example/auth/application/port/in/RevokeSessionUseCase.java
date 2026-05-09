package com.example.auth.application.port.in;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import java.util.UUID;

public interface RevokeSessionUseCase {

    void revoke(Command cmd);

    record Command(TenantId tenantId, UserId userId, UUID sessionId, String ipAddress) {
    }
}
