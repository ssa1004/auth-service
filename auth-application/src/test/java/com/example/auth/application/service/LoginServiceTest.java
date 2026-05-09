package com.example.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.exception.MfaRequiredException;
import com.example.auth.application.exception.RateLimitedException;
import com.example.auth.application.port.in.LoginUseCase;
import com.example.auth.application.security.AuthProperties;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.user.User;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LoginServiceTest {

    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private final AuthProperties props = AuthProperties.defaults();

    private InMemoryFakes.FakeUserRepository users;
    private InMemoryFakes.FakeTenantRepository tenants;
    private InMemoryFakes.FakeRoleRepository roles;
    private InMemoryFakes.FakeRefreshTokenRepository refresh;
    private InMemoryFakes.FakePasswordHasher hasher;
    private InMemoryFakes.AlwaysAllowRateLimiter allowLimiter;
    private InMemoryFakes.FakeMfaChallengeStore challenges;
    private InMemoryFakes.StubAccessTokenIssuer accessIssuer;
    private InMemoryFakes.CountingRefreshTokenGenerator refreshGen;
    private InMemoryFakes.CapturingAuditLog auditLog;
    private AuditLoginAttemptsService auditService;
    private SessionIssuer sessionIssuer;
    private LoginService service;
    private Tenant tenant;
    private UserId aliceId;

    @BeforeEach
    void setUp() {
        users = new InMemoryFakes.FakeUserRepository();
        tenants = new InMemoryFakes.FakeTenantRepository();
        roles = new InMemoryFakes.FakeRoleRepository();
        refresh = new InMemoryFakes.FakeRefreshTokenRepository();
        hasher = new InMemoryFakes.FakePasswordHasher();
        allowLimiter = new InMemoryFakes.AlwaysAllowRateLimiter();
        challenges = new InMemoryFakes.FakeMfaChallengeStore();
        accessIssuer = new InMemoryFakes.StubAccessTokenIssuer();
        refreshGen = new InMemoryFakes.CountingRefreshTokenGenerator();
        auditLog = new InMemoryFakes.CapturingAuditLog();
        auditService = new AuditLoginAttemptsService(auditLog, clock);
        sessionIssuer = new SessionIssuer(accessIssuer, refreshGen, refresh, roles, props, clock);

        service = new LoginService(
                users, tenants, hasher, allowLimiter, challenges, sessionIssuer, auditService, props);

        tenant = tenants.save(Tenant.create("acme", "ACME", clock.instant()));
        User alice = User.register(tenant.id(), "alice@example.com",
                hasher.hash("supersecret123"), clock.instant()).markVerified(clock.instant());
        aliceId = users.save(alice).id();
    }

    @Test
    void 정상_로그인은_access_와_refresh_둘_다_발급() {
        var tokens = service.login(new LoginUseCase.Command(
                "acme", "alice@example.com", "supersecret123",
                "1.2.3.4", "ua", "macbook"));

        assertThat(tokens.accessToken()).startsWith("stub-jwt.");
        assertThat(tokens.refreshToken()).startsWith("rt-");
        assertThat(refresh.size()).isEqualTo(1);
        assertThat(auditLog.events()).extracting("type").contains(AuditEventType.LOGIN_SUCCEEDED);
    }

    @Test
    void 비밀번호_불일치는_InvalidCredentials() {
        assertThatThrownBy(() -> service.login(new LoginUseCase.Command(
                "acme", "alice@example.com", "wrong", "1.2.3.4", "ua", "macbook")))
                .isInstanceOf(InvalidCredentialsException.class);
        assertThat(auditLog.events()).extracting("type")
                .contains(AuditEventType.LOGIN_FAILED_BAD_CREDENTIALS);
    }

    @Test
    void 사용자_미존재여도_같은_예외_같은_메시지_정보_누설_금지() {
        assertThatThrownBy(() -> service.login(new LoginUseCase.Command(
                "acme", "ghost@example.com", "anything", "1.2.3.4", "ua", "macbook")))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("invalid credentials");
        // bad credentials 와 같은 메시지를 응답한다 — bad_credentials 이벤트로 audit 기록.
        assertThat(auditLog.events()).extracting("type")
                .contains(AuditEventType.LOGIN_FAILED_BAD_CREDENTIALS);
    }

    @Test
    void LOCKED_사용자는_InvalidCredentials_그러나_audit_은_LOCKED_로_기록() {
        users.save(users.findById(tenant.id(), aliceId).orElseThrow().lock(clock.instant()));

        assertThatThrownBy(() -> service.login(new LoginUseCase.Command(
                "acme", "alice@example.com", "supersecret123", "1.2.3.4", "ua", "macbook")))
                .isInstanceOf(InvalidCredentialsException.class);
        assertThat(auditLog.events()).extracting("type")
                .contains(AuditEventType.LOGIN_FAILED_USER_LOCKED);
    }

    @Test
    void MFA_활성_사용자는_MfaRequired_예외_던지고_access_미발급() {
        users.save(users.findById(tenant.id(), aliceId).orElseThrow().enableMfa(clock.instant()));

        assertThatThrownBy(() -> service.login(new LoginUseCase.Command(
                "acme", "alice@example.com", "supersecret123", "1.2.3.4", "ua", "macbook")))
                .isInstanceOf(MfaRequiredException.class);
        // access / refresh 미발급
        assertThat(refresh.size()).isZero();
        assertThat(auditLog.events()).extracting("type").contains(AuditEventType.MFA_REQUIRED);
    }

    @Test
    void rate_limit_차단_시_RateLimited_예외_그리고_audit() {
        var deny = new InMemoryFakes.FixedDenyRateLimiter();
        var blocked = new LoginService(
                users, tenants, hasher, deny, challenges, sessionIssuer, auditService, props);
        assertThatThrownBy(() -> blocked.login(new LoginUseCase.Command(
                "acme", "alice@example.com", "supersecret123", "1.2.3.4", "ua", "macbook")))
                .isInstanceOf(RateLimitedException.class);
        assertThat(auditLog.events()).extracting("type")
                .contains(AuditEventType.LOGIN_FAILED_RATE_LIMITED);
    }

    @Test
    void access_token_의_amr_은_pwd_만() {
        service.login(new LoginUseCase.Command(
                "acme", "alice@example.com", "supersecret123", "1.2.3.4", "ua", "macbook"));
        assertThat(accessIssuer.lastClaims.amr()).containsExactly("pwd");
    }
}
