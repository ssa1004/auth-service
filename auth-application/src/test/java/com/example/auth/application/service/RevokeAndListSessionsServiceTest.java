package com.example.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.port.in.LoginUseCase;
import com.example.auth.application.port.in.RevokeSessionUseCase;
import com.example.auth.application.security.AuthProperties;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.token.RefreshTokenStatus;
import com.example.auth.domain.user.User;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RevokeAndListSessionsServiceTest {

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
    private LoginService loginService;
    private RevokeSessionService revokeService;
    private ListMySessionsService listService;
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
        loginService = new LoginService(
                users, tenants, hasher, allowLimiter, challenges, sessionIssuer, auditService, props);
        revokeService = new RevokeSessionService(refresh, auditService, clock);
        listService = new ListMySessionsService(refresh);

        tenant = tenants.save(Tenant.create("acme", "ACME", clock.instant()));
        User alice = User.register(tenant.id(), "alice@example.com",
                hasher.hash("supersecret123"), clock.instant()).markVerified(clock.instant());
        aliceId = users.save(alice).id();

        loginService.login(new LoginUseCase.Command(
                "acme", "alice@example.com", "supersecret123", "1.2.3.4", "ua", "macbook"));
        loginService.login(new LoginUseCase.Command(
                "acme", "alice@example.com", "supersecret123", "5.6.7.8", "ua2", "iphone"));
    }

    @Test
    void list_는_사용자의_활성_세션을_모두_반환() {
        var sessions = listService.list(tenant.id(), aliceId);

        assertThat(sessions).hasSize(2);
        assertThat(sessions).extracting("deviceLabel").containsExactlyInAnyOrder("macbook", "iphone");
    }

    @Test
    void revoke_는_해당_세션만_REVOKED_BY_USER_나머지는_그대로() {
        var sessions = listService.list(tenant.id(), aliceId);
        var first = sessions.get(0);

        revokeService.revoke(new RevokeSessionUseCase.Command(
                tenant.id(), aliceId, first.sessionId(), "1.2.3.4"));

        // 활성은 1개만
        assertThat(listService.list(tenant.id(), aliceId)).hasSize(1);
        assertThat(refresh.all())
                .filteredOn(t -> t.id().equals(first.sessionId()))
                .allMatch(t -> t.status() == RefreshTokenStatus.REVOKED_BY_USER);
        assertThat(auditLog.events()).extracting("type")
                .contains(AuditEventType.SESSION_REVOKED_BY_USER);
    }

    @Test
    void 다른_사용자의_세션_revoke_시도는_거부() {
        var bob = User.register(tenant.id(), "bob@example.com",
                hasher.hash("anotherpw1234"), clock.instant()).markVerified(clock.instant());
        users.save(bob);
        // bob 이 alice 의 세션 id 를 안다고 가정.
        var alicesSession = listService.list(tenant.id(), aliceId).get(0);

        assertThatThrownBy(() -> revokeService.revoke(new RevokeSessionUseCase.Command(
                tenant.id(), bob.id(), alicesSession.sessionId(), "9.9.9.9")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void 모르는_session_id_revoke_는_InvalidCredentials() {
        assertThatThrownBy(() -> revokeService.revoke(new RevokeSessionUseCase.Command(
                tenant.id(), aliceId, UUID.randomUUID(), "1.2.3.4")))
                .isInstanceOf(InvalidCredentialsException.class);
    }
}
