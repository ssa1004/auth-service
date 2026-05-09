package com.example.auth.adapter.out.persistence.audit;

import com.example.auth.application.port.out.AuditLogRepository;
import com.example.auth.domain.audit.AuditEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Audit append + SIEM outbox 동시 INSERT (ADR-0012).
 *
 * <p>같은 트랜잭션 안에서 두 row 를 INSERT 합니다. 트랜잭션이 commit 되어야 둘 다
 * 살아남으므로 "audit 만 적재되고 SIEM 으로 못 흐른" 사고가 발생하지 않습니다.
 */
@Repository
@RequiredArgsConstructor
public class AuditLogRepositoryAdapter implements AuditLogRepository {

    /** SIEM 발행 토픽 — 본 단계는 한 종류만. 다른 도메인 이벤트가 추가되면 확장. */
    public static final String AUDIT_TOPIC = "auth.audit";

    private final AuditEventJpaRepository auditJpa;
    private final AuditEventOutboxJpaRepository outboxJpa;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    @Override
    @Transactional
    public AuditEvent append(AuditEvent event) {
        AuditEvent saved = auditJpa.save(AuditEventEntity.from(event)).toDomain();
        String payloadJson = serialize(saved);
        outboxJpa.save(AuditEventOutboxEntity.create(
                saved.id(), AUDIT_TOPIC, payloadJson, clock.instant()));
        return saved;
    }

    /**
     * SIEM 측 schema (JSON):
     * <pre>
     * {
     *   "eventId": "...",            // audit_events.id
     *   "occurredAt": "ISO-8601",
     *   "tenantId": "...",
     *   "actor": "userId or null",   // 미인증 실패는 null
     *   "action": "LOGIN_SUCCESS|...",
     *   "ip": "...",
     *   "userAgent": "...",
     *   "payload": { ... }           // 자유 형식. 비밀번호 / 토큰 평문 금지.
     * }
     * </pre>
     */
    private String serialize(AuditEvent e) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("eventId", e.id().toString());
        root.put("occurredAt", e.occurredAt().toString());
        root.put("tenantId", e.tenantId().value().toString());
        root.put("actor", e.userId() == null ? null : e.userId().value().toString());
        root.put("action", e.type().name());
        root.put("ip", e.ipAddress());
        root.put("userAgent", e.userAgent());
        root.put("payload", e.payload());
        try {
            return objectMapper.writeValueAsString(root);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("audit outbox 직렬화 실패", ex);
        }
    }
}
