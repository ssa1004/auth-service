package com.example.auth.domain.audit;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;

/**
 * Append-only audit 이벤트. 한 번 적재되면 절대 수정되지 않습니다 (ADR-0008).
 *
 * <p>{@code payload} 는 자유 형식 JSON-able map. 단, 평문 비밀번호 / TOTP secret /
 * refresh token 평문은 절대 들어가서는 안 됩니다 — application 에서 호출 전에 마스킹된
 * 형태로만 넘겨야 합니다.
 */
public record AuditEvent(
        UUID id,
        TenantId tenantId,
        UserId userId,
        AuditEventType type,
        String ipAddress,
        String userAgent,
        Map<String, String> payload,
        Instant occurredAt) {

    public AuditEvent {
        Objects.requireNonNull(id);
        Objects.requireNonNull(tenantId);
        Objects.requireNonNull(type);
        Objects.requireNonNull(occurredAt);
        payload = payload == null ? Map.of() : Map.copyOf(new TreeMap<>(payload));
        // userId 는 미인증 실패 시점 (로그인 실패 — username 못 찾음) 에는 null 가능.
    }

    public static AuditEvent of(
            TenantId tenantId,
            UserId userId,
            AuditEventType type,
            String ipAddress,
            String userAgent,
            Map<String, String> payload,
            Instant now) {
        return new AuditEvent(UUID.randomUUID(), tenantId, userId, type, ipAddress, userAgent, payload, now);
    }
}
