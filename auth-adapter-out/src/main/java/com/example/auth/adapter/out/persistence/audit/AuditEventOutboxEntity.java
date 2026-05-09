package com.example.auth.adapter.out.persistence.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * Audit 이벤트의 SIEM (Kafka) 발행 outbox row (ADR-0012).
 *
 * <p>같은 트랜잭션에서 audit_events row 와 함께 INSERT — DB 트랜잭션이 commit 되어야
 * outbox 가 살아남으므로 "audit 만 적재되고 SIEM 으로 못 흐른" 케이스가 없다. 발행은
 * 별도 worker 가 폴링해서 처리.
 */
@Entity
@Table(name = "audit_event_outbox")
public class AuditEventOutboxEntity {

    @Id
    private UUID id;

    @Column(name = "audit_event_id", nullable = false)
    private UUID auditEventId;

    @Column(nullable = false)
    private String topic;

    @Column(name = "payload_json", nullable = false)
    private String payloadJson;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "published_at")
    private Instant publishedAt;

    @Column(name = "attempt_count", nullable = false)
    private int attemptCount;

    @Column(name = "last_error")
    private String lastError;

    protected AuditEventOutboxEntity() {}

    public static AuditEventOutboxEntity create(
            UUID auditEventId, String topic, String payloadJson, Instant now) {
        AuditEventOutboxEntity ent = new AuditEventOutboxEntity();
        ent.id = UUID.randomUUID();
        ent.auditEventId = auditEventId;
        ent.topic = topic;
        ent.payloadJson = payloadJson;
        ent.createdAt = now;
        ent.attemptCount = 0;
        return ent;
    }

    public UUID getId() {
        return id;
    }

    public UUID getAuditEventId() {
        return auditEventId;
    }

    public String getTopic() {
        return topic;
    }

    public String getPayloadJson() {
        return payloadJson;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getPublishedAt() {
        return publishedAt;
    }

    public int getAttemptCount() {
        return attemptCount;
    }

    public String getLastError() {
        return lastError;
    }

    /** 발행 성공 시점 박제. */
    public void markPublished(Instant now) {
        this.publishedAt = now;
        this.lastError = null;
    }

    /** 실패 카운트 + 사유 기록 — 다음 폴링 사이클에 재시도. */
    public void markFailed(String error) {
        this.attemptCount++;
        // last_error 컬럼이 너무 길어지지 않도록 자르기.
        this.lastError = error == null ? null : error.substring(0, Math.min(error.length(), 480));
    }
}
