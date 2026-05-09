package com.example.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.exception.RefreshReuseDetectedException;
import com.example.auth.application.port.in.LoginUseCase;
import com.example.auth.application.port.in.RefreshTokenUseCase;
import com.example.auth.application.security.AuthProperties;
import com.example.auth.application.security.AuthTokens;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.token.RefreshTokenStatus;
import com.example.auth.domain.user.User;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RefreshTokenServiceTest {

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
    private RefreshTokenService refreshService;
    private Tenant tenant;
    private AuthTokens initialTokens;

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
        refreshService = new RefreshTokenService(
                refresh, users, tenants, sessionIssuer, auditService, props, clock);

        tenant = tenants.save(Tenant.create("acme", "ACME", clock.instant()));
        User alice = User.register(tenant.id(), "alice@example.com",
                hasher.hash("supersecret123"), clock.instant()).markVerified(clock.instant());
        users.save(alice);
        initialTokens = loginService.login(new LoginUseCase.Command(
                "acme", "alice@example.com", "supersecret123", "1.2.3.4", "ua", "macbook"));
    }

    @Test
    void 정상_refresh_는_새_토큰_발급_그리고_기존_토큰은_ROTATED() {
        AuthTokens rotated = refreshService.refresh(new RefreshTokenUseCase.Command(
                initialTokens.refreshToken(), "1.2.3.4", "ua"));

        assertThat(rotated.refreshToken()).isNotEqualTo(initialTokens.refreshToken());
        // 기존 token 상태는 REVOKED_ROTATED
        assertThat(refresh.all()).anyMatch(t -> t.status() == RefreshTokenStatus.REVOKED_ROTATED);
        assertThat(auditLog.events()).extracting("type").contains(AuditEventType.REFRESH_ROTATED);
    }

    @Test
    void 회전된_token_을_다시_사용하면_reuse_detection_으로_모든_세션_revoke() {
        // 첫 번째 회전 — 정상.
        AuthTokens t1 = refreshService.refresh(new RefreshTokenUseCase.Command(
                initialTokens.refreshToken(), "1.2.3.4", "ua"));
        // 사용자가 같은 디바이스에서 두 번째 로그인하여 다른 활성 세션도 생성.
        loginService.login(new LoginUseCase.Command(
                "acme", "alice@example.com", "supersecret123", "1.2.3.4", "ua", "iphone"));

        // 이제 *이미 회전된* initial refresh 를 다시 사용하면 reuse signal.
        // grace 윈도우 우회 — IP 가 다르면 즉시 reuse 로 간주.
        assertThatThrownBy(() -> refreshService.refresh(new RefreshTokenUseCase.Command(
                initialTokens.refreshToken(), "9.9.9.9", "ua")))
                .isInstanceOf(RefreshReuseDetectedException.class);

        // 사용자의 모든 refresh 가 REVOKED_REUSE_DETECTED
        assertThat(refresh.all())
                .filteredOn(t -> t.status() != RefreshTokenStatus.REVOKED_ROTATED)
                .allMatch(t -> t.status() == RefreshTokenStatus.REVOKED_REUSE_DETECTED);

        // audit 에도 reuse 이벤트
        assertThat(auditLog.events()).extracting("type")
                .contains(AuditEventType.REFRESH_REUSE_DETECTED);
    }

    @Test
    void 모르는_token_은_InvalidCredentials() {
        assertThatThrownBy(() -> refreshService.refresh(new RefreshTokenUseCase.Command(
                "garbage", "1.2.3.4", "ua")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void 만료된_token_은_InvalidCredentials() {
        // 시계를 미래로 보내는 별도 service 인스턴스
        Clock future = Clock.fixed(clock.instant().plus(Duration.ofDays(31)), ZoneOffset.UTC);
        RefreshTokenService futureService = new RefreshTokenService(
                refresh, users, tenants, sessionIssuer, auditService, props, future);

        assertThatThrownBy(() -> futureService.refresh(new RefreshTokenUseCase.Command(
                initialTokens.refreshToken(), "1.2.3.4", "ua")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void 사용자가_revoke_한_세션의_token_은_사용_불가() {
        var active = refresh.all().iterator().next();
        refresh.save(active.markRevokedByUser(clock.instant()));

        assertThatThrownBy(() -> refreshService.refresh(new RefreshTokenUseCase.Command(
                initialTokens.refreshToken(), "1.2.3.4", "ua")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    /**
     * grace 윈도우 안의 retry — 같은 IP, 5초 안 → 401 만 (revoke 안 함).
     * 모바일 client 의 jitter 에 의한 정당한 재요청 시나리오 보호.
     */
    @Test
    void 회전_직후_같은_IP_에서_retry_는_revoke_없이_401() {
        // 1. 정상 회전
        refreshService.refresh(new RefreshTokenUseCase.Command(
                initialTokens.refreshToken(), "1.2.3.4", "ua"));

        // 2. 같은 IP / UA 로 즉시 재시도 (mobile retry 시나리오) — grace 안
        assertThatThrownBy(() -> refreshService.refresh(new RefreshTokenUseCase.Command(
                initialTokens.refreshToken(), "1.2.3.4", "ua")))
                .isInstanceOf(InvalidCredentialsException.class);

        // 3. 사용자의 다른 active 세션은 그대로 유지 — 일괄 revoke 미발동
        long stillActive = refresh.all().stream()
                .filter(t -> t.status() == RefreshTokenStatus.ACTIVE)
                .count();
        assertThat(stillActive).isPositive();
        // REUSE_DETECTED 은 audit 에도 안 박힘
        assertThat(auditLog.events()).extracting("type")
                .doesNotContain(AuditEventType.REFRESH_REUSE_DETECTED);
    }

    /** grace 윈도우 밖 retry — 시계 진행 후엔 reuse detection 정상 발동. */
    @Test
    void 회전_후_grace_윈도우_지나면_같은_IP_라도_reuse_detection() {
        refreshService.refresh(new RefreshTokenUseCase.Command(
                initialTokens.refreshToken(), "1.2.3.4", "ua"));

        // grace 5초 + 1초 = 6초 진행한 별도 인스턴스
        Clock laterClock = Clock.fixed(clock.instant().plus(Duration.ofSeconds(6)), ZoneOffset.UTC);
        RefreshTokenService laterService = new RefreshTokenService(
                refresh, users, tenants, sessionIssuer, auditService, props, laterClock);

        assertThatThrownBy(() -> laterService.refresh(new RefreshTokenUseCase.Command(
                initialTokens.refreshToken(), "1.2.3.4", "ua")))
                .isInstanceOf(RefreshReuseDetectedException.class);
    }
}
