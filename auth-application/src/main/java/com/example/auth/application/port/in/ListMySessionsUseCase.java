package com.example.auth.application.port.in;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface ListMySessionsUseCase {

    List<SessionView> list(TenantId tenantId, UserId userId);

    record SessionView(
            UUID sessionId,
            String deviceLabel,
            String ipAddress,
            Instant issuedAt,
            Instant lastUsedAt,
            Instant expiresAt) {
    }
}
