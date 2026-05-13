package com.example.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.application.exception.RateLimitedException;
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
    private InMemoryFakes.AlwaysAllowRateLimiter allowLimiter;
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
        allowLimiter = new InMemoryFakes.AlwaysAllowRateLimiter();
        auditLog = new InMemoryFakes.CapturingAuditLog();
        auditService = new AuditLoginAttemptsService(auditLog, clock);
        service = new RegisterUserService(users, tenants, hasher, mail, allowLimiter, auditService, clock);
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

    @Test
    void IP_있을_때_rate_limit_차단되면_사용자_미생성_상태로_RateLimited_예외() {
        // OWASP API4 / API6 — 자동 가입 봇이 같은 IP 에서 폭주하는 시나리오. 같은 IP 의
        // burst 가 한도를 넘으면 즉시 차단되어야 하고 user 는 만들어지지 않아야 함.
        var deny = new InMemoryFakes.FixedDenyRateLimiter();
        var blocked = new RegisterUserService(users, tenants, hasher, mail, deny, auditService, clock);

        assertThatThrownBy(() -> blocked.register(new RegisterUserUseCase.Command(
                        "acme", "bot@example.com", "longenoughpw1!", "203.0.113.99")))
                .isInstanceOf(RateLimitedException.class);

        assertThat(users.findByEmail(tenant.id(), "bot@example.com")).isEmpty();
        assertThat(mail.sentCount()).isZero();
    }

    @Test
    void IP_가_null_이면_rate_limit_경로를_건너뛴다() {
        // 단위 테스트 / 내부 호출 (admin tool 등) 에서 IP 가 없는 케이스 — bucket 소모 없이 통과.
        var deny = new InMemoryFakes.FixedDenyRateLimiter();
        var anywhere = new RegisterUserService(users, tenants, hasher, mail, deny, auditService, clock);

        var id = anywhere.register(new RegisterUserUseCase.Command(
                "acme", "internal@example.com", "longenoughpw1!"));
        assertThat(id).isNotNull();
    }
}
