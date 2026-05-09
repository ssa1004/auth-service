package com.example.auth.adapter.out.persistence.audit;

import com.example.auth.domain.audit.AuditEvent;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "audit_events")
public class AuditEventEntity {

    @Transient
    private static final ObjectMapper MAPPER = new ObjectMapper();
    @Transient
    private static final TypeReference<Map<String, String>> MAP_TYPE = new TypeReference<>() {};

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "user_id")
    private UUID userId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditEventType type;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "payload_json", nullable = false)
    private String payloadJson;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    protected AuditEventEntity() {}

    public static AuditEventEntity from(AuditEvent e) {
        AuditEventEntity ent = new AuditEventEntity();
        ent.id = e.id();
        ent.tenantId = e.tenantId().value();
        ent.userId = e.userId() == null ? null : e.userId().value();
        ent.type = e.type();
        ent.ipAddress = e.ipAddress();
        ent.userAgent = e.userAgent();
        try {
            ent.payloadJson = MAPPER.writeValueAsString(e.payload());
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("audit payload 직렬화 실패", ex);
        }
        ent.occurredAt = e.occurredAt();
        return ent;
    }

    public AuditEvent toDomain() {
        Map<String, String> payload;
        try {
            payload = payloadJson == null ? new HashMap<>() : MAPPER.readValue(payloadJson, MAP_TYPE);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("audit payload 역직렬화 실패", ex);
        }
        return new AuditEvent(
                id, TenantId.of(tenantId),
                userId == null ? null : UserId.of(userId),
                type, ipAddress, userAgent, payload, occurredAt);
    }
}
