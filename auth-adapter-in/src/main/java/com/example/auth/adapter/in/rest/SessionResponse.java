package com.example.auth.adapter.in.rest;

import com.example.auth.application.port.in.ListMySessionsUseCase.SessionView;
import java.time.Instant;
import java.util.UUID;

public record SessionResponse(
        UUID sessionId,
        String deviceLabel,
        String ipAddress,
        Instant issuedAt,
        Instant lastUsedAt,
        Instant expiresAt) {

    public static SessionResponse from(SessionView v) {
        return new SessionResponse(
                v.sessionId(), v.deviceLabel(), v.ipAddress(),
                v.issuedAt(), v.lastUsedAt(), v.expiresAt());
    }
}
