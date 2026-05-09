package com.example.auth.application.authz;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.application.service.AuditLoginAttemptsService;
import com.example.auth.application.service.InMemoryFakes;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class PolicyDecisionServiceTest {

    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private final InMemoryFakes.CapturingAuditLog auditLog = new InMemoryFakes.CapturingAuditLog();
    private final AuditLoginAttemptsService auditService = new AuditLoginAttemptsService(auditLog, clock);

    @Test
    void allow_결정은_POLICY_DECISION_ALLOW_audit_으로_적재() {
        var port = new InMemoryFakes.AlwaysAllowPolicyDecisionPort();
        var service = new PolicyDecisionService(port, auditService);

        var result = service.evaluate("auth/session/revoke", sampleRequest("session.revoke"));

        assertThat(result.allow()).isTrue();
        assertThat(auditLog.events()).extracting("type").contains(AuditEventType.POLICY_DECISION_ALLOW);
        assertThat(auditLog.events().get(0).payload())
                .containsEntry("policyPath", "auth/session/revoke")
                .containsEntry("action", "session.revoke")
                .containsEntry("allow", "true");
    }

    @Test
    void deny_결정은_POLICY_DECISION_DENY_와_reasons_가_payload_에() {
        var port = new InMemoryFakes.AlwaysDenyPolicyDecisionPort("not_resource_owner");
        var service = new PolicyDecisionService(port, auditService);

        var result = service.evaluate("auth/session/revoke", sampleRequest("session.revoke"));

        assertThat(result.allow()).isFalse();
        assertThat(result.reasons()).containsExactly("not_resource_owner");
        assertThat(auditLog.events()).extracting("type").contains(AuditEventType.POLICY_DECISION_DENY);
        assertThat(auditLog.events().get(0).payload())
                .containsEntry("reasons", "not_resource_owner");
    }

    @Test
    void port_가_예외를_던지면_fail_closed_로_deny() {
        PolicyDecisionPort throwing = (path, req) -> { throw new RuntimeException("boom"); };
        var service = new PolicyDecisionService(throwing, auditService);

        var result = service.evaluate("auth/session/revoke", sampleRequest("session.revoke"));

        assertThat(result.allow()).isFalse();
        assertThat(result.reasons()).containsExactly("policy_evaluation_error");
    }

    private PolicyDecisionRequest sampleRequest(String action) {
        TenantId tenantId = TenantId.newId();
        UserId userId = UserId.of(UUID.randomUUID());
        return new PolicyDecisionRequest(
                new PolicyDecisionRequest.Subject(
                        tenantId, userId, Set.of("user"), Set.of(), Map.of()),
                action,
                new PolicyDecisionRequest.Resource("session", tenantId, userId, Map.of()),
                Map.of("ip", "1.2.3.4"));
    }
}
