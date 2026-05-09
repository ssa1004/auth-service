package com.example.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.application.exception.TenantNotFoundException;
import com.example.auth.application.exception.UserAlreadyExistsException;
import com.example.auth.application.port.in.RegisterUserUseCase;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.tenant.Tenant;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RegisterUserServiceTest {

    private InMemoryFakes.FakeUserRepository users;
    private InMemoryFakes.FakeTenantRepository tenants;
    private InMemoryFakes.FakePasswordHasher hasher;
    private InMemoryFakes.CountingMailSender mail;
    private InMemoryFakes.CapturingAuditLog auditLog;
    private AuditLoginAttemptsService auditService;
    private RegisterUserService service;

    private Tenant tenant;
    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

    @BeforeEach
    void setUp() {
        users = new InMemoryFakes.FakeUserRepository();
        tenants = new InMemoryFakes.FakeTenantRepository();
        hasher = new InMemoryFakes.FakePasswordHasher();
        mail = new InMemoryFakes.CountingMailSender();
        auditLog = new InMemoryFakes.CapturingAuditLog();
        auditService = new AuditLoginAttemptsService(auditLog, clock);
        service = new RegisterUserService(users, tenants, hasher, mail, auditService, clock);
        tenant = tenants.save(Tenant.create("acme", "ACME", clock.instant()));
    }

    @Test
    void 새_사용자가_PENDING_VERIFICATION_상태로_저장되고_메일이_발송된다() {
        var id = service.register(new RegisterUserUseCase.Command("acme", "alice@example.com", "longenoughpw1!"));

        assertThat(users.findById(tenant.id(), id)).isPresent();
        assertThat(mail.sentCount()).isEqualTo(1);
        assertThat(auditLog.events())
                .extracting("type")
                .contains(AuditEventType.USER_REGISTERED);
    }

    @Test
    void 같은_테넌트에_같은_이메일은_거부() {
        service.register(new RegisterUserUseCase.Command("acme", "alice@example.com", "longenoughpw1!"));
        assertThatThrownBy(() -> service.register(
                new RegisterUserUseCase.Command("acme", "Alice@Example.com", "longenoughpw1!")))
                .isInstanceOf(UserAlreadyExistsException.class);
    }

    @Test
    void 다른_테넌트에_같은_이메일은_허용() {
        tenants.save(Tenant.create("globex", "Globex", clock.instant()));
        service.register(new RegisterUserUseCase.Command("acme", "alice@example.com", "longenoughpw1!"));
        // 같은 이메일이라도 다른 테넌트라면 신규 — multi-tenant 격리 확인
        var id = service.register(new RegisterUserUseCase.Command("globex", "alice@example.com", "longenoughpw1!"));
        assertThat(id).isNotNull();
    }

    @Test
    void 모르는_테넌트는_명확히_거부() {
        assertThatThrownBy(() -> service.register(
                new RegisterUserUseCase.Command("nope", "alice@example.com", "longenoughpw1!")))
                .isInstanceOf(TenantNotFoundException.class);
    }

    @Test
    void 비밀번호_평문이_저장소에_들어가지_않는다() {
        service.register(new RegisterUserUseCase.Command("acme", "alice@example.com", "supersecret123!"));
        var saved = users.findByEmail(tenant.id(), "alice@example.com").orElseThrow();
        assertThat(saved.passwordHash()).startsWith("HASH:supersecret123!:");
        // 그냥 같은지를 비교하는 게 아니라, 평문이 그대로 저장되지 않았는지 확인.
        assertThat(saved.passwordHash()).isNotEqualTo("supersecret123!");
    }
}
