package com.example.auth.adapter.out.persistence.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.auth.domain.audit.AuditEvent;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * AuditLogRepositoryAdapter (ADR-0012) — append 시 audit row + outbox row 가
 * 같은 트랜잭션에서 INSERT 되는지, 그리고 JSON schema 가 합의된 모양 (eventId / actor /
 * action ...) 인지를 검증.
 */
class AuditLogRepositoryAdapterTest {

    private AuditEventJpaRepository auditJpa;
    private AuditEventOutboxJpaRepository outboxJpa;
    private ObjectMapper objectMapper;
    private Clock clock;
    private AuditLogRepositoryAdapter adapter;

    @BeforeEach
    void setUp() {
        auditJpa = mock(AuditEventJpaRepository.class);
        outboxJpa = mock(AuditEventOutboxJpaRepository.class);
        objectMapper = new ObjectMapper();
        clock = Clock.fixed(Instant.parse("2026-05-09T10:00:00Z"), ZoneOffset.UTC);
        adapter = new AuditLogRepositoryAdapter(auditJpa, outboxJpa, objectMapper, clock);

        // auditJpa.save 는 받은 entity 를 그대로 반환 (id 가 그대로 살아남는 편이 도메인 비교 쉬움).
        when(auditJpa.save(any(AuditEventEntity.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void append_시_audit_row_와_outbox_row_가_둘다_INSERT_된다() throws Exception {
        AuditEvent event = AuditEvent.of(
                TenantId.of(UUID.fromString("11111111-1111-1111-1111-111111111111")),
                UserId.of(UUID.fromString("22222222-2222-2222-2222-222222222222")),
                AuditEventType.LOGIN_SUCCEEDED,
                "203.0.113.10",
                "Mozilla/5.0",
                Map.of("device", "iPhone"),
                Instant.parse("2026-05-09T10:00:00Z"));

        adapter.append(event);

        verify(auditJpa).save(any(AuditEventEntity.class));

        ArgumentCaptor<AuditEventOutboxEntity> outboxCaptor =
                ArgumentCaptor.forClass(AuditEventOutboxEntity.class);
        verify(outboxJpa).save(outboxCaptor.capture());

        AuditEventOutboxEntity outbox = outboxCaptor.getValue();
        assertThat(outbox.getTopic()).isEqualTo("auth.audit");
        assertThat(outbox.getAuditEventId()).isEqualTo(event.id());
        assertThat(outbox.getCreatedAt()).isEqualTo(Instant.parse("2026-05-09T10:00:00Z"));
        assertThat(outbox.getPublishedAt()).isNull();
        assertThat(outbox.getAttemptCount()).isZero();

        // SIEM JSON schema — 합의된 키 모두 존재.
        @SuppressWarnings("unchecked")
        Map<String, Object> json = objectMapper.readValue(outbox.getPayloadJson(), Map.class);
        assertThat(json).containsKeys(
                "eventId", "occurredAt", "tenantId", "actor", "action", "ip", "userAgent", "payload");
        assertThat(json.get("action")).isEqualTo("LOGIN_SUCCEEDED");
        assertThat(json.get("ip")).isEqualTo("203.0.113.10");
        assertThat(json.get("userAgent")).isEqualTo("Mozilla/5.0");
        assertThat(json.get("actor")).isEqualTo(event.userId().value().toString());
    }

    @Test
    void 미인증_실패_audit_은_actor_가_null() throws Exception {
        AuditEvent event = AuditEvent.of(
                TenantId.of(UUID.randomUUID()),
                null, // username 못 찾은 케이스
                AuditEventType.LOGIN_FAILED_BAD_CREDENTIALS,
                "10.0.0.1",
                "curl/8.0",
                Map.of("emailMasked", "u***@d***.com"),
                Instant.parse("2026-05-09T10:00:00Z"));

        adapter.append(event);

        ArgumentCaptor<AuditEventOutboxEntity> outboxCaptor =
                ArgumentCaptor.forClass(AuditEventOutboxEntity.class);
        verify(outboxJpa).save(outboxCaptor.capture());

        @SuppressWarnings("unchecked")
        Map<String, Object> json = objectMapper.readValue(outboxCaptor.getValue().getPayloadJson(), Map.class);
        assertThat(json.get("actor")).isNull();
        assertThat(json.get("action")).isEqualTo("LOGIN_FAILED_BAD_CREDENTIALS");
    }
}
