package com.example.auth.adapter.out.persistence.audit

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

/**
 * Audit 이벤트의 SIEM (Kafka) 발행 outbox row (ADR-0012).
 *
 * 같은 트랜잭션에서 audit_events row 와 함께 INSERT — DB 트랜잭션이 commit 되어야
 * outbox 가 살아남으므로 "audit 만 적재되고 SIEM 으로 못 흐른" 케이스가 없다. 발행은
 * 별도 worker 가 폴링해서 처리.
 */
@Entity
@Table(name = "audit_event_outbox")
class AuditEventOutboxEntity {

    @Id
    private var id: UUID = UUID(0, 0)

    @Column(name = "audit_event_id", nullable = false)
    private var auditEventId: UUID = UUID(0, 0)

    @Column(nullable = false)
    private var topic: String = ""

    @Column(name = "payload_json", nullable = false)
    private var payloadJson: String = ""

    @Column(name = "created_at", nullable = false)
    private var createdAt: Instant = Instant.EPOCH

    @Column(name = "published_at")
    private var publishedAt: Instant? = null

    @Column(name = "attempt_count", nullable = false)
    private var attemptCount: Int = 0

    @Column(name = "last_error")
    private var lastError: String? = null

    fun getId(): UUID = id
    fun getAuditEventId(): UUID = auditEventId
    fun getTopic(): String = topic
    fun getPayloadJson(): String = payloadJson
    fun getCreatedAt(): Instant = createdAt
    fun getPublishedAt(): Instant? = publishedAt
    fun getAttemptCount(): Int = attemptCount
    fun getLastError(): String? = lastError

    /** 발행 성공 시점 기록. */
    fun markPublished(now: Instant) {
        this.publishedAt = now
        this.lastError = null
    }

    /** 실패 카운트 + 사유 기록 — 다음 폴링 사이클에 재시도. */
    fun markFailed(error: String?) {
        this.attemptCount++
        // last_error 컬럼이 너무 길어지지 않도록 자르기.
        this.lastError = error?.substring(0, minOf(error.length, 480))
    }

    companion object {
        @JvmStatic
        fun create(
            auditEventId: UUID,
            topic: String,
            payloadJson: String,
            now: Instant,
        ): AuditEventOutboxEntity = AuditEventOutboxEntity().apply {
            this.id = UUID.randomUUID()
            this.auditEventId = auditEventId
            this.topic = topic
            this.payloadJson = payloadJson
            this.createdAt = now
            this.attemptCount = 0
        }
    }
}
