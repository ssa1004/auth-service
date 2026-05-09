package com.example.auth.application.service;

import com.example.auth.application.authz.PolicyDecisionRequest;
import com.example.auth.application.authz.PolicyDecisionResult;
import com.example.auth.application.authz.PolicyDecisionService;
import com.example.auth.application.exception.PolicyDeniedException;
import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.in.RevokeTokenByAdminUseCase;
import com.example.auth.application.port.out.AccessTokenBlocklist;
import com.example.auth.application.port.out.AccessTokenIntrospector;
import com.example.auth.application.port.out.RefreshTokenRepository;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.token.RefreshToken;
import com.example.auth.domain.token.TokenHasher;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * RFC 7009 Token Revocation 구현 (ADR-0018).
 *
 * <p>호출 흐름:
 * <ol>
 *   <li>OPA 정책 {@code auth/token/revoke} 평가 — 호출 client 가 {@code token.revoke}
 *       scope 보유 여부 확인. 거부 시 PolicyDenied → 403.</li>
 *   <li>token_type_hint 가 access_token 이면 JWT 디코드 → jti 를 Redis 블록리스트에
 *       잔여 유효시간 TTL 로 추가. introspection 호출 즉시 active=false 응답.</li>
 *   <li>token_type_hint 가 refresh_token 이면 hash 로 lookup → REVOKED_BY_ADMIN 마킹.</li>
 *   <li>hint 가 없으면 access → refresh 순으로 시도. 둘 다 실패해도 RFC 7009 §2.2 에
 *       따라 호출자에게는 200 만 반환 (정보 누설 차단).</li>
 *   <li>모든 결과를 audit 에 {@code TOKEN_REVOKED_BY_ADMIN} 로 기록.</li>
 * </ol>
 *
 * <p>본 service 자체는 HTTP 응답 형식과 무관 — controller 가 항상 200 응답을 보장합니다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RevokeTokenByAdminService implements RevokeTokenByAdminUseCase {

    private static final String HINT_REFRESH = "refresh_token";

    private final AccessTokenIntrospector accessTokenIntrospector;
    private final AccessTokenBlocklist accessTokenBlocklist;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PolicyDecisionService policyDecisionService;
    private final AuditLoginAttemptsUseCase auditUseCase;
    private final Clock clock;

    @Override
    @Transactional
    public void revoke(Command cmd) {
        Outcome outcome = doRevoke(cmd);
        recordAudit(cmd, outcome);
    }

    private Outcome doRevoke(Command cmd) {
        // 1) OPA gate — admin scope 검증. 거부 시 PolicyDenied 가 throw.
        evaluatePolicy(cmd);

        // 2) hint 따라 우선 형식 결정. 첫 번째 시도에서 실패 시 다른 형식으로 fallback.
        boolean refreshFirst = HINT_REFRESH.equals(cmd.tokenTypeHint());
        if (refreshFirst) {
            Optional<Outcome> refreshOutcome = revokeRefresh(cmd.token());
            if (refreshOutcome.isPresent()) return refreshOutcome.get();
            return revokeAccess(cmd.token()).orElse(Outcome.unknown());
        }
        Optional<Outcome> accessOutcome = revokeAccess(cmd.token());
        if (accessOutcome.isPresent()) return accessOutcome.get();
        return revokeRefresh(cmd.token()).orElse(Outcome.unknown());
    }

    private void evaluatePolicy(Command cmd) {
        // 호출자는 client_credentials 의 client — 사용자 컨텍스트가 없으므로 nil UUID 로
        // PolicyDecisionRequest 의 non-null 가드를 통과시키고, OPA 정책은 attributes 의
        // clientId / scopes 만 보고 결정합니다.
        TenantId nilTenant = TenantId.of(NIL_UUID);
        UserId nilUser = UserId.of(NIL_UUID);
        PolicyDecisionRequest request = new PolicyDecisionRequest(
                new PolicyDecisionRequest.Subject(
                        nilTenant, nilUser,
                        Set.of(), Set.of(),
                        Map.of(
                                "clientId", cmd.callerClient() == null ? "" : cmd.callerClient(),
                                "scopes", cmd.callerScopes())),
                "token.revoke",
                new PolicyDecisionRequest.Resource(
                        "token", nilTenant, null, Map.of()),
                cmd.ipAddress() == null ? Map.of() : Map.of("ip", cmd.ipAddress()));
        PolicyDecisionResult decision = policyDecisionService.evaluate("auth/token/revoke", request);
        if (!decision.allow()) {
            throw new PolicyDeniedException(decision.reasons());
        }
    }

    /** RFC 4122 의 nil UUID — "사용자 컨텍스트 없음" 을 표현하는 sentinel. */
    private static final java.util.UUID NIL_UUID = new java.util.UUID(0L, 0L);

    private Optional<Outcome> revokeAccess(String token) {
        Optional<AccessTokenIntrospector.Decoded> decoded = accessTokenIntrospector.decode(token);
        if (decoded.isEmpty()) return Optional.empty();
        AccessTokenIntrospector.Decoded d = decoded.get();
        Instant now = clock.instant();
        if (d.expiresAt() != null) {
            Duration remaining = Duration.between(now, d.expiresAt());
            if (remaining.isNegative() || remaining.isZero()) {
                // 이미 만료된 access — 적재할 필요 없음. 호출자 시각에서는 revoke 성공으로 간주.
                return Optional.of(Outcome.access(d, Duration.ZERO));
            }
            accessTokenBlocklist.add(d.jwtId(), remaining);
            return Optional.of(Outcome.access(d, remaining));
        }
        // exp 없는 비정상 토큰 — 안전을 위해 한 시간 임의 TTL 로 차단.
        accessTokenBlocklist.add(d.jwtId(), Duration.ofHours(1));
        return Optional.of(Outcome.access(d, Duration.ofHours(1)));
    }

    private Optional<Outcome> revokeRefresh(String token) {
        if (looksLikeJwt(token)) return Optional.empty();
        String hash = TokenHasher.sha256(token);
        Optional<RefreshToken> found = refreshTokenRepository.findByTokenHashReadOnly(hash);
        if (found.isEmpty()) return Optional.empty();
        RefreshToken rt = found.get();
        // 이미 종료된 토큰도 RFC 7009 §2.2 에 따라 200. 그러나 다시 마킹할 필요는 없음.
        if (rt.status() != com.example.auth.domain.token.RefreshTokenStatus.ACTIVE) {
            return Optional.of(Outcome.refresh(rt, false));
        }
        refreshTokenRepository.save(rt.markRevokedByAdmin(clock.instant()));
        return Optional.of(Outcome.refresh(rt, true));
    }

    private void recordAudit(Command cmd, Outcome outcome) {
        try {
            Map<String, String> payload = new LinkedHashMap<>();
            payload.put("result", outcome.kind);
            if (cmd.tokenTypeHint() != null) payload.put("hint", cmd.tokenTypeHint());
            if (cmd.callerClient() != null) payload.put("client", cmd.callerClient());
            if (outcome.jti != null) payload.put("jti", outcome.jti);
            if (outcome.sessionId != null) payload.put("sessionId", outcome.sessionId);
            if (outcome.blocklistTtlSeconds >= 0) {
                payload.put("blocklistTtlSeconds", String.valueOf(outcome.blocklistTtlSeconds));
            }
            // tenantId 는 audit 의 non-null 가드 충족용. unknown 결과는 nil UUID 로 기록.
            TenantId tenant = outcome.tenantId != null ? outcome.tenantId : TenantId.of(NIL_UUID);
            auditUseCase.record(
                    tenant, outcome.userId,
                    AuditEventType.TOKEN_REVOKED_BY_ADMIN,
                    cmd.ipAddress(), null, payload);
        } catch (RuntimeException e) {
            log.warn("admin token revoke audit 적재 실패", e);
        }
    }

    private static boolean looksLikeJwt(String token) {
        int firstDot = token.indexOf('.');
        if (firstDot <= 0) return false;
        int secondDot = token.indexOf('.', firstDot + 1);
        return secondDot > firstDot;
    }

    /** 결과 묶음 — audit 기록을 위한 내부 구조. */
    private record Outcome(
            String kind,
            TenantId tenantId,
            UserId userId,
            String jti,
            String sessionId,
            long blocklistTtlSeconds) {

        static Outcome unknown() {
            return new Outcome("unknown", null, null, null, null, -1);
        }

        static Outcome access(AccessTokenIntrospector.Decoded d, Duration ttl) {
            return new Outcome(
                    "access",
                    d.tenantId() != null ? TenantId.of(d.tenantId()) : null,
                    d.subject() != null ? UserId.of(d.subject()) : null,
                    d.jwtId(), null,
                    ttl == null ? -1 : ttl.toSeconds());
        }

        static Outcome refresh(RefreshToken rt, boolean newlyRevoked) {
            return new Outcome(
                    newlyRevoked ? "refresh" : "refresh_already_inactive",
                    rt.tenantId(), rt.userId(), null, rt.id().toString(), -1);
        }
    }
}
