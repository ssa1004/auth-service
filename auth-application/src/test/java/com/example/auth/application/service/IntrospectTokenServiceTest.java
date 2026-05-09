package com.example.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.application.port.in.IntrospectTokenUseCase;
import com.example.auth.application.port.in.IntrospectTokenUseCase.Result;
import com.example.auth.application.port.out.AccessTokenBlocklist;
import com.example.auth.application.port.out.AccessTokenIntrospector;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.token.RefreshToken;
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
 * IntrospectTokenService 의 RFC 7662 응답 매핑 + revoke 연동 검증 (ADR-0017).
 */
class IntrospectTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-05-09T00:00:00Z");
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    private InMemoryFakes.FakeRefreshTokenRepository refresh;
    private InMemoryFakes.CapturingAuditLog auditLog;
    private AuditLoginAttemptsService auditService;
    private StubAccessTokenIntrospector introspector;
    private InMemoryAccessTokenBlocklist blocklist;
    private IntrospectTokenService service;

    @BeforeEach
    void setUp() {
        refresh = new InMemoryFakes.FakeRefreshTokenRepository();
        auditLog = new InMemoryFakes.CapturingAuditLog();
        auditService = new AuditLoginAttemptsService(auditLog, clock);
        introspector = new StubAccessTokenIntrospector();
        blocklist = new InMemoryAccessTokenBlocklist();
        service = new IntrospectTokenService(introspector, blocklist, refresh, auditService, clock);
    }

    @Test
    void 유효한_access_jwt_는_active_true_와_표준_claim_을_반환() {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        introspector.register("ey.head.payload.sig",
                new AccessTokenIntrospector.Decoded(
                        userId.toString(), tenantId.toString(),
                        "https://auth.example.com", "internal-service",
                        "jti-123",
                        List.of("admin"),
                        List.of("api:read", "api:write"),
                        NOW.minusSeconds(60),
                        NOW.plusSeconds(900),
                        Map.of()));

        Result r = service.introspect(new IntrospectTokenUseCase.Command(
                "ey.head.payload.sig", "access_token", "internal-service"));

        assertThat(r.active()).isTrue();
        assertThat(r.tokenType()).isEqualTo("Bearer");
        assertThat(r.subject()).isEqualTo(userId.toString());
        assertThat(r.tenantId()).isEqualTo(tenantId.toString());
        assertThat(r.roles()).containsExactly("admin");
        assertThat(r.scope()).isEqualTo("api:read api:write");
        assertThat(r.jwtId()).isEqualTo("jti-123");
        assertThat(r.issuer()).isEqualTo("https://auth.example.com");
        assertThat(r.clientId()).isEqualTo("internal-service");
        assertThat(r.expiresAt()).isEqualTo(NOW.plusSeconds(900));

        assertThat(auditLog.events()).extracting("type")
                .contains(AuditEventType.TOKEN_INTROSPECTED);
    }

    @Test
    void 만료된_access_jwt_는_active_false() {
        introspector.register("expired.token.x",
                new AccessTokenIntrospector.Decoded(
                        UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                        "iss", "aud", "jti-exp",
                        List.of(), List.of(),
                        NOW.minusSeconds(3600),
                        NOW.minusSeconds(60),  // 이미 만료
                        Map.of()));

        Result r = service.introspect(new IntrospectTokenUseCase.Command(
                "expired.token.x", "access_token", "internal-service"));

        assertThat(r.active()).isFalse();
        assertThat(r.subject()).isNull();
    }

    @Test
    void blocklist_에_있는_jti_는_active_false_admin_revoke_즉시_반영() {
        introspector.register("ey.live.token",
                new AccessTokenIntrospector.Decoded(
                        UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                        "iss", "aud", "blocked-jti",
                        List.of(), List.of(),
                        NOW.minusSeconds(60), NOW.plusSeconds(600),
                        Map.of()));
        blocklist.add("blocked-jti", Duration.ofSeconds(600));

        Result r = service.introspect(new IntrospectTokenUseCase.Command(
                "ey.live.token", "access_token", "internal-service"));

        assertThat(r.active()).isFalse();
    }

    @Test
    void 알_수_없는_token_은_inactive_정보_누설_없음() {
        // introspector 가 디코드 실패, refresh 도 존재 X
        Result r = service.introspect(new IntrospectTokenUseCase.Command(
                "completely-unknown-token", null, "internal-service"));

        assertThat(r.active()).isFalse();
        assertThat(r.subject()).isNull();
        assertThat(r.tenantId()).isNull();
        assertThat(r.scope()).isNull();
    }

    @Test
    void 활성_refresh_token_은_active_true_와_subject_반환() {
        TenantId tenant = TenantId.of(UUID.randomUUID());
        UserId user = UserId.of(UUID.randomUUID());
        String plain = "rt-" + UUID.randomUUID();
        String hash = TokenHasher.sha256(plain);
        var rt = RefreshToken.issue(
                tenant, user, hash, null,
                "macbook", "1.2.3.4",
                NOW.minusSeconds(120),
                NOW.plus(Duration.ofDays(30)));
        refresh.save(rt);

        Result r = service.introspect(new IntrospectTokenUseCase.Command(
                plain, "refresh_token", "internal-service"));

        assertThat(r.active()).isTrue();
        assertThat(r.tokenType()).isEqualTo("refresh");
        assertThat(r.subject()).isEqualTo(user.asString());
        assertThat(r.tenantId()).isEqualTo(tenant.asString());
        assertThat(r.expiresAt()).isAfter(NOW);
    }

    @Test
    void revoke_된_refresh_token_은_active_false() {
        TenantId tenant = TenantId.of(UUID.randomUUID());
        UserId user = UserId.of(UUID.randomUUID());
        String plain = "rt-" + UUID.randomUUID();
        String hash = TokenHasher.sha256(plain);
        var rt = RefreshToken.issue(
                tenant, user, hash, null, null, null,
                NOW.minusSeconds(120), NOW.plus(Duration.ofDays(30)));
        refresh.save(rt.markRevokedByAdmin(NOW));

        Result r = service.introspect(new IntrospectTokenUseCase.Command(
                plain, "refresh_token", "internal-service"));

        assertThat(r.active()).isFalse();
    }

    /** AccessTokenIntrospector stub — 등록된 token 만 디코드, 그 외는 empty. */
    static final class StubAccessTokenIntrospector implements AccessTokenIntrospector {
        private final java.util.Map<String, Decoded> registry = new java.util.HashMap<>();

        void register(String token, Decoded decoded) {
            registry.put(token, decoded);
        }

        @Override
        public Optional<Decoded> decode(String token) {
            return Optional.ofNullable(registry.get(token));
        }
    }

    /** AccessTokenBlocklist 의 in-memory 구현. TTL 은 단위 테스트 범위 밖이라 무시. */
    static final class InMemoryAccessTokenBlocklist implements AccessTokenBlocklist {
        private final Set<String> set = new HashSet<>();

        @Override
        public void add(String jwtId, Duration ttl) {
            if (jwtId != null) set.add(jwtId);
        }

        @Override
        public boolean contains(String jwtId) {
            return jwtId != null && set.contains(jwtId);
        }
    }
}
