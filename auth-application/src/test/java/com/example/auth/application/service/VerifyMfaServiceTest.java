package com.example.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.exception.MfaRequiredException;
import com.example.auth.application.exception.RateLimitedException;
import com.example.auth.application.port.in.LoginUseCase;
import com.example.auth.application.port.in.VerifyMfaUseCase;
import com.example.auth.application.security.AuthProperties;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.mfa.MfaMethod;
import com.example.auth.domain.mfa.MfaSecret;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.user.User;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class VerifyMfaServiceTest {

    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private final AuthProperties props = AuthProperties.defaults();

    private InMemoryFakes.FakeUserRepository users;
    private InMemoryFakes.FakeTenantRepository tenants;
    private InMemoryFakes.FakeRoleRepository roles;
    private InMemoryFakes.FakeRefreshTokenRepository refresh;
    private InMemoryFakes.FakePasswordHasher hasher;
    private InMemoryFakes.FakeMfaChallengeStore challenges;
    private InMemoryFakes.StubAccessTokenIssuer accessIssuer;
    private InMemoryFakes.CountingRefreshTokenGenerator refreshGen;
    private InMemoryFakes.CapturingAuditLog auditLog;
    private AuditLoginAttemptsService auditService;
    private SessionIssuer sessionIssuer;
    private LoginService loginService;
    private VerifyMfaService verifyService;
    private InMemoryFakes.FakeMfaSecretRepository mfaSecrets;
    private InMemoryFakes.IdentityCipher cipher;
    private InMemoryFakes.StubTotpVerifier totp;
    private Tenant tenant;
    private String challengeToken;

    @BeforeEach
    void setUp() {
        users = new InMemoryFakes.FakeUserRepository();
        tenants = new InMemoryFakes.FakeTenantRepository();
        roles = new InMemoryFakes.FakeRoleRepository();
        refresh = new InMemoryFakes.FakeRefreshTokenRepository();
        hasher = new InMemoryFakes.FakePasswordHasher();
        challenges = new InMemoryFakes.FakeMfaChallengeStore();
        accessIssuer = new InMemoryFakes.StubAccessTokenIssuer();
        refreshGen = new InMemoryFakes.CountingRefreshTokenGenerator();
        auditLog = new InMemoryFakes.CapturingAuditLog();
        auditService = new AuditLoginAttemptsService(auditLog, clock);
        sessionIssuer = new SessionIssuer(accessIssuer, refreshGen, refresh, roles, props, clock);
        mfaSecrets = new InMemoryFakes.FakeMfaSecretRepository();
        cipher = new InMemoryFakes.IdentityCipher();
        totp = new InMemoryFakes.StubTotpVerifier();
        loginService = new LoginService(
                users, tenants, hasher, new InMemoryFakes.AlwaysAllowRateLimiter(),
                challenges, sessionIssuer, auditService, props);
        verifyService = new VerifyMfaService(
                challenges, users, tenants, mfaSecrets, cipher, totp,
                new InMemoryFakes.AlwaysAllowRateLimiter(), sessionIssuer, auditService);

        tenant = tenants.save(Tenant.create("acme", "ACME", clock.instant()));
        User alice = User.register(tenant.id(), "alice@example.com",
                hasher.hash("supersecret123"), clock.instant())
                .markVerified(clock.instant())
                .enableMfa(clock.instant());
        users.save(alice);
        mfaSecrets.save(MfaSecret.enroll(alice.id(),
                cipher.encrypt("JBSWY3DPEHPK3PXP"), MfaMethod.TOTP, clock.instant())
                .confirm(clock.instant()));

        try {
            loginService.login(new LoginUseCase.Command(
                    "acme", "alice@example.com", "supersecret123", "1.2.3.4", "ua", "macbook"));
            throw new AssertionError("MFA 활성 사용자는 MfaRequiredException 던져야 함");
        } catch (MfaRequiredException ex) {
            challengeToken = ex.mfaChallengeToken();
        }
    }

    @Test
    void 정상_TOTP_코드는_access_와_refresh_발급() {
        var tokens = verifyService.verify(new VerifyMfaUseCase.Command(
                challengeToken, "123456", "1.2.3.4", "ua", "macbook"));

        assertThat(tokens.accessToken()).startsWith("stub-jwt.");
        assertThat(tokens.refreshToken()).isNotBlank();
        assertThat(accessIssuer.lastClaims.amr()).containsExactlyInAnyOrder("pwd", "mfa");
        assertThat(auditLog.events()).extracting("type").contains(AuditEventType.MFA_VERIFIED);
    }

    @Test
    void 잘못된_TOTP_코드는_InvalidCredentials() {
        assertThatThrownBy(() -> verifyService.verify(new VerifyMfaUseCase.Command(
                challengeToken, "999999", "1.2.3.4", "ua", "macbook")))
                .isInstanceOf(InvalidCredentialsException.class);
        assertThat(auditLog.events()).extracting("type").contains(AuditEventType.MFA_FAILED);
    }

    @Test
    void challenge_token_은_단_1회_만_사용_가능_replay_차단() {
        verifyService.verify(new VerifyMfaUseCase.Command(
                challengeToken, "123456", "1.2.3.4", "ua", "macbook"));
        // 같은 challenge 로 두 번째 시도 — 첫 호출이 consume 했으므로 이미 없음.
        assertThatThrownBy(() -> verifyService.verify(new VerifyMfaUseCase.Command(
                challengeToken, "123456", "1.2.3.4", "ua", "macbook")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void 모르는_challenge_token_은_InvalidCredentials() {
        assertThatThrownBy(() -> verifyService.verify(new VerifyMfaUseCase.Command(
                "fake-mfa-challenge", "123456", "1.2.3.4", "ua", "macbook")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void IP_있을_때_rate_limit_초과_시_RateLimited_예외_challenge_는_소비되지_않음() {
        var blocked = new VerifyMfaService(
                challenges, users, tenants, mfaSecrets, cipher, totp,
                new InMemoryFakes.FixedDenyRateLimiter(), sessionIssuer, auditService);

        assertThatThrownBy(() -> blocked.verify(new VerifyMfaUseCase.Command(
                challengeToken, "123456", "1.2.3.4", "ua", "macbook")))
                .isInstanceOf(RateLimitedException.class);
        // rate limit 은 challenge consume 보다 먼저 — 차단돼도 challenge 는 살아있어
        // 정상 한도 안에서는 같은 mfaToken 으로 인증을 이어갈 수 있음.
        var tokens = verifyService.verify(new VerifyMfaUseCase.Command(
                challengeToken, "123456", "1.2.3.4", "ua", "macbook"));
        assertThat(tokens.accessToken()).startsWith("stub-jwt.");
    }
}
