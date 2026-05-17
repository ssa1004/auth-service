package com.example.auth.adapter.out.persistence.audit

import com.example.auth.domain.audit.AuditEvent
import com.example.auth.domain.audit.AuditEventType
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "audit_events")
class AuditEventEntity {

    @Id
    private var id: UUID = UUID(0, 0)

    @Column(name = "tenant_id", nullable = false)
    private var tenantId: UUID = UUID(0, 0)

    @Column(name = "user_id")
    private var userId: UUID? = null

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private var type: AuditEventType = AuditEventType.LOGIN_SUCCEEDED

    @Column(name = "ip_address")
    private var ipAddress: String? = null

    @Column(name = "user_agent")
    private var userAgent: String? = null

    @Column(name = "payload_json", nullable = false)
    private var payloadJson: String = "{}"

    @Column(name = "occurred_at", nullable = false)
    private var occurredAt: Instant = Instant.EPOCH

    fun toDomain(): AuditEvent {
        val payload: Map<String, String> = try {
            if (payloadJson.isBlank()) emptyMap() else MAPPER.readValue(payloadJson, MAP_TYPE)
        } catch (ex: JsonProcessingException) {
            throw IllegalStateException("audit payload 역직렬화 실패", ex)
        }
        return AuditEvent(
            id, TenantId.of(tenantId),
            userId?.let { UserId.of(it) },
            type, ipAddress, userAgent, payload, occurredAt,
        )
    }

    companion object {

        @JvmStatic
        private val MAPPER: ObjectMapper = ObjectMapper()

        @JvmStatic
        private val MAP_TYPE: TypeReference<Map<String, String>> = object : TypeReference<Map<String, String>>() {}

        @JvmStatic
        fun from(e: AuditEvent): AuditEventEntity = AuditEventEntity().apply {
            id = e.id
            tenantId = e.tenantId.value
            userId = e.userId?.value
            type = e.type
            ipAddress = e.ipAddress
            userAgent = e.userAgent
            payloadJson = try {
                MAPPER.writeValueAsString(e.payload)
            } catch (ex: JsonProcessingException) {
                throw IllegalStateException("audit payload 직렬화 실패", ex)
            }
            occurredAt = e.occurredAt
        }
    }
}
