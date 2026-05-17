package com.example.auth.adapter.out.persistence.audit

import com.example.auth.application.port.out.AuditLogRepository
import com.example.auth.domain.audit.AuditEvent
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import java.time.Clock
import java.util.LinkedHashMap
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional

/**
 * Audit append + SIEM outbox 동시 INSERT (ADR-0012).
 *
 * 같은 트랜잭션 안에서 두 row 를 INSERT 합니다. 트랜잭션이 commit 되어야 둘 다
 * 살아남으므로 "audit 만 적재되고 SIEM 으로 못 흐른" 사고가 발생하지 않습니다.
 */
@Repository
class AuditLogRepositoryAdapter(
    private val auditJpa: AuditEventJpaRepository,
    private val outboxJpa: AuditEventOutboxJpaRepository,
    private val objectMapper: ObjectMapper,
    private val clock: Clock,
) : AuditLogRepository {

    @Transactional
    override fun append(event: AuditEvent): AuditEvent {
        val saved = auditJpa.save(AuditEventEntity.from(event)).toDomain()
        val payloadJson = serialize(saved)
        outboxJpa.save(
            AuditEventOutboxEntity.create(saved.id, AUDIT_TOPIC, payloadJson, clock.instant()),
        )
        return saved
    }

    /**
     * SIEM 측 schema (JSON):
     * ```
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
     * ```
     */
    private fun serialize(e: AuditEvent): String {
        val root = LinkedHashMap<String, Any?>()
        root["eventId"] = e.id.toString()
        root["occurredAt"] = e.occurredAt.toString()
        root["tenantId"] = e.tenantId.value.toString()
        root["actor"] = e.userId?.value?.toString()
        root["action"] = e.type.name
        root["ip"] = e.ipAddress
        root["userAgent"] = e.userAgent
        root["payload"] = e.payload
        return try {
            objectMapper.writeValueAsString(root)
        } catch (ex: JsonProcessingException) {
            throw IllegalStateException("audit outbox 직렬화 실패", ex)
        }
    }

    companion object {
        /** SIEM 발행 토픽 — 본 단계는 한 종류만. 다른 도메인 이벤트가 추가되면 확장. */
        @JvmField
        val AUDIT_TOPIC: String = "auth.audit"
    }
}
