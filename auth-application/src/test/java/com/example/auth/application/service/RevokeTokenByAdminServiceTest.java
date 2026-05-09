package com.example.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.application.authz.PolicyDecisionRequest;
import com.example.auth.application.authz.PolicyDecisionResult;
import com.example.auth.application.authz.PolicyDecisionService;
import com.example.auth.application.exception.PolicyDeniedException;
import com.example.auth.application.port.in.RevokeTokenByAdminUseCase;
import com.example.auth.application.port.out.AccessTokenBlocklist;
import com.example.auth.application.port.out.AccessTokenIntrospector;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.token.RefreshToken;
import com.example.auth.domain.token.RefreshTokenStatus;
import com.example.auth.domain.token.TokenHasher;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * RevokeTokenByAdminService 의 OPA gate + access blocklist + refresh 마킹 검증 (ADR-0018).
 */
class RevokeTokenByAdminServiceTest {

    private static final Instant NOW = Instant.parse("2026-05-09T01:00:00Z");
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    private InMemoryFakes.FakeRefreshTokenRepository refresh;
    private InMemoryFakes.CapturingAuditLog auditLog;
    private AuditLoginAttemptsService auditService;
    private IntrospectTokenServiceTest.StubAccessTokenIntrospector introspector;
    private IntrospectTokenServiceTest.InMemoryAccessTokenBlocklist blocklist;
    private RevokeTokenByAdminService service;
    private PolicyDecisionService policyDecisionService;

    @BeforeEach
    void setUp() {
        refresh = new InMemoryFakes.FakeRefreshTokenRepository();
        auditLog = new InMemoryFakes.CapturingAuditLog();
        auditService = new AuditLoginAttemptsService(auditLog, clock);
        introspector = new IntrospectTokenServiceTest.StubAccessTokenIntrospector();
        blocklist = new IntrospectTokenServiceTest.InMemoryAccessTokenBlocklist();
        // OPA 정책의 in-process 평가 — token.revoke scope 보유 시 allow.
        policyDecisionService = new PolicyDecisionService(
                (path, req) -> {
                    Object scopes = req.subject().attributes().get("scopes");
                    boolean ok = scopes instanceof java.util.Collection<?> col
                            && col.stream().map(String::valueOf).anyMatch("token.revoke"::equals);
                    return ok ? PolicyDecisionResult.allowed()
                              : PolicyDecisionResult.denied("missing_token_revoke_scope");
                }, auditService);
        service = new RevokeTokenByAdminService(
                introspector, blocklist, refresh, policyDecisionService, auditService, clock);
    }

    @Test
    void access_revoke_시_jti_가_blocklist_에_잔여_TTL_로_등록() {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        introspector.register("ey.access.token",
                new AccessTokenIntrospector.Decoded(
                        userId.toString(), tenantId.toString(),
                        "iss", "internal-service", "jti-revoke",
                        List.of(), List.of(),
                        NOW.minusSeconds(60), NOW.plusSeconds(600),
                        Map.of()));

        service.revoke(new RevokeTokenByAdminUseCase.Command(
                "ey.access.token", "access_token", "internal-admin",
                Set.of("token.revoke"), "10.0.0.1"));

        assertThat(blocklist.contains("jti-revoke")).isTrue();
        assertThat(auditLog.events()).extracting("type")
                .contains(AuditEventType.TOKEN_REVOKED_BY_ADMIN);
    }

    @Test
    void refresh_revoke_시_REVOKED_BY_ADMIN_으로_마킹() {
        TenantId tenant = TenantId.of(UUID.randomUUID());
        UserId user = UserId.of(UUID.randomUUID());
        String plain = "rt-" + UUID.randomUUID();
        String hash = TokenHasher.sha256(plain);
        var rt = RefreshToken.issue(
                tenant, user, hash, null, null, null,
                NOW.minusSeconds(120), NOW.plus(Duration.ofDays(30)));
        refresh.save(rt);

        service.revoke(new RevokeTokenByAdminUseCase.Command(
                plain, "refresh_token", "internal-admin",
                Set.of("token.revoke"), "10.0.0.1"));

        var stored = refresh.all().iterator().next();
        assertThat(stored.status()).isEqualTo(RefreshTokenStatus.REVOKED_BY_ADMIN);
    }

    @Test
    void admin_scope_없으면_PolicyDenied() {
        introspector.register("ey.access.token",
                new AccessTokenIntrospector.Decoded(
                        UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                        "iss", "aud", "jti", List.of(), List.of(),
                        NOW.minusSeconds(10), NOW.plusSeconds(600),
                        Map.of()));

        assertThatThrownBy(() -> service.revoke(new RevokeTokenByAdminUseCase.Command(
                "ey.access.token", "access_token", "regular-client",
                Set.of("api.read"), "10.0.0.1")))
                .isInstanceOf(PolicyDeniedException.class);

        assertThat(blocklist.contains("jti")).isFalse();
    }

    @Test
    void 알_수_없는_token_도_정상_종료_정보_누설_없음() {
        // 어떤 token 도 등록되지 않음 — service 는 unknown outcome 으로 audit 만 남기고 종료.
        service.revoke(new RevokeTokenByAdminUseCase.Command(
                "totally-unknown", null, "internal-admin",
                Set.of("token.revoke"), "10.0.0.1"));

        assertThat(auditLog.events()).extracting("type")
                .contains(AuditEventType.TOKEN_REVOKED_BY_ADMIN);
    }

    @Test
    void revoke_후_introspect_는_active_false_검증_e2e_의존성_없는_단위_레벨() {
        // 같은 fake 위에서 IntrospectTokenService 도 만들어 통합 흐름 검증.
        IntrospectTokenService introspect = new IntrospectTokenService(
                introspector, blocklist, refresh, auditService, clock);

        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        introspector.register("ey.access.live",
                new AccessTokenIntrospector.Decoded(
                        userId.toString(), tenantId.toString(),
                        "iss", "aud", "jti-live",
                        List.of(), List.of(),
                        NOW.minusSeconds(60), NOW.plusSeconds(600),
                        Map.of()));

        // 1) 처음에는 active=true
        var before = introspect.introspect(new com.example.auth.application.port.in.IntrospectTokenUseCase.Command(
                "ey.access.live", "access_token", "internal-service"));
        assertThat(before.active()).isTrue();

        // 2) admin revoke
        service.revoke(new RevokeTokenByAdminUseCase.Command(
                "ey.access.live", "access_token", "internal-admin",
                Set.of("token.revoke"), "10.0.0.1"));

        // 3) 다시 introspect → active=false
        var after = introspect.introspect(new com.example.auth.application.port.in.IntrospectTokenUseCase.Command(
                "ey.access.live", "access_token", "internal-service"));
        assertThat(after.active()).isFalse();
    }
}
