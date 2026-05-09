package com.example.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.application.authz.PolicyDecisionService;
import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.exception.PolicyDeniedException;
import com.example.auth.application.port.in.AssignRoleUseCase;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.role.Permission;
import com.example.auth.domain.role.Role;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.user.User;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AssignRoleServiceTest {

    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

    private InMemoryFakes.FakeUserRepository users;
    private InMemoryFakes.FakeRoleRepository roles;
    private InMemoryFakes.CapturingAuditLog auditLog;
    private InMemoryFakes.AlwaysAllowPolicyDecisionPort policyPort;
    private AuditLoginAttemptsService auditService;
    private PolicyDecisionService policyDecisionService;
    private AssignRoleService service;
    private Tenant acme;
    private Tenant globex;
    private UserId aliceId;
    private UserId actorId;
    private Role billingOperator;

    @BeforeEach
    void setUp() {
        users = new InMemoryFakes.FakeUserRepository();
        roles = new InMemoryFakes.FakeRoleRepository();
        auditLog = new InMemoryFakes.CapturingAuditLog();
        auditService = new AuditLoginAttemptsService(auditLog, clock);
        policyPort = new InMemoryFakes.AlwaysAllowPolicyDecisionPort();
        policyDecisionService = new PolicyDecisionService(policyPort, auditService);
        service = new AssignRoleService(users, roles, auditService, policyDecisionService);
        acme = new Tenant(com.example.auth.domain.common.TenantId.newId(), "acme", "ACME",
                com.example.auth.domain.tenant.TenantStatus.ACTIVE, clock.instant());
        globex = new Tenant(com.example.auth.domain.common.TenantId.newId(), "globex", "Globex",
                com.example.auth.domain.tenant.TenantStatus.ACTIVE, clock.instant());

        aliceId = users.save(User.register(acme.id(), "alice@example.com",
                "HASHHASHHASHHASHHASH", clock.instant()).markVerified(clock.instant())).id();
        actorId = users.save(User.register(acme.id(), "admin@example.com",
                "HASHHASHHASHHASHHASH", clock.instant()).markVerified(clock.instant())).id();
        billingOperator = roles.save(Role.create(acme.id(), "billing-operator", "Billing Operator",
                Set.of(Permission.of("billing:read"), Permission.of("billing:write"))));
    }

    @Test
    void assign_은_사용자에_role_을_부여하고_audit_기록() {
        service.assign(new AssignRoleUseCase.Command(
                acme.id(), aliceId, billingOperator.id(), actorId, "1.2.3.4"));

        assertThat(roles.findByUser(acme.id(), aliceId))
                .extracting(Role::slug)
                .containsExactly("billing-operator");
        assertThat(auditLog.events()).extracting("type").contains(AuditEventType.ROLE_ASSIGNED);
    }

    @Test
    void 다른_테넌트의_role_부여는_거부() {
        // alice 는 acme 테넌트인데 globex 의 role id 로 시도.
        Role globexRole = roles.save(Role.create(globex.id(), "viewer", "Viewer",
                Set.of(Permission.of("billing:read"))));

        assertThatThrownBy(() -> service.assign(new AssignRoleUseCase.Command(
                acme.id(), aliceId, globexRole.id(), actorId, "1.2.3.4")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void 모르는_role_id_부여는_거부() {
        assertThatThrownBy(() -> service.assign(new AssignRoleUseCase.Command(
                acme.id(), aliceId, UUID.randomUUID(), actorId, "1.2.3.4")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void 정책이_거부하면_PolicyDeniedException_으로_막힘() {
        AssignRoleService denyingService = new AssignRoleService(
                users, roles, auditService,
                new PolicyDecisionService(
                        new InMemoryFakes.AlwaysDenyPolicyDecisionPort("admin_role_requires_senior_admin"),
                        auditService));

        assertThatThrownBy(() -> denyingService.assign(new AssignRoleUseCase.Command(
                acme.id(), aliceId, billingOperator.id(), actorId, "1.2.3.4")))
                .isInstanceOf(PolicyDeniedException.class);

        // role 부여까지 가지 않았는지 확인.
        assertThat(roles.findByUser(acme.id(), aliceId)).isEmpty();
    }

    @Test
    void 정책_평가도_audit_으로_적재() {
        service.assign(new AssignRoleUseCase.Command(
                acme.id(), aliceId, billingOperator.id(), actorId, "1.2.3.4"));

        // 정책 결정과 ROLE_ASSIGNED 둘 다 audit 에 남아있어야 함.
        assertThat(auditLog.events()).extracting("type")
                .contains(AuditEventType.POLICY_DECISION_ALLOW, AuditEventType.ROLE_ASSIGNED);
        assertThat(policyPort.calls).contains("auth/role/assign:role.assign");
    }
}
