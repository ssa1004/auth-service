package com.example.auth.application.service;

import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.in.IntrospectTokenUseCase;
import com.example.auth.application.port.out.AccessTokenBlocklist;
import com.example.auth.application.port.out.AccessTokenIntrospector;
import com.example.auth.application.port.out.RefreshTokenRepository;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.token.RefreshToken;
import com.example.auth.domain.token.RefreshTokenStatus;
import com.example.auth.domain.token.TokenHasher;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * RFC 7662 Token Introspection 구현 (ADR-0017).
 *
 * <p>처리 순서:
 * <ol>
 *   <li>token_type_hint 가 있으면 그 형식부터 시도 — 빠른 경로.</li>
 *   <li>access JWT 디코드 (서명 / 만료 검증) → 성공 시 jti 가 blocklist 에 있는지 확인.</li>
 *   <li>JWT 가 아니라면 refresh token 으로 가정하여 hash → DB 조회. ACTIVE 만 active=true.</li>
 *   <li>두 형식 모두 실패하면 RFC 7662 §2.2 에 따라 {@code {"active":false}} — 정보 누설 X.</li>
 * </ol>
 *
 * <p>본 service 는 audit 에 introspect 결과 (active 여부 + 호출 client) 만 기록합니다 —
 * 토큰 평문 / 사용자 PII 는 적재하지 않습니다 (ISMS-P 적합성).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IntrospectTokenService implements IntrospectTokenUseCase {

    private static final String TOKEN_TYPE_BEARER = "Bearer";
    private static final String HINT_ACCESS = "access_token";
    private static final String HINT_REFRESH = "refresh_token";

    private final AccessTokenIntrospector accessTokenIntrospector;
    private final AccessTokenBlocklist accessTokenBlocklist;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuditLoginAttemptsUseCase auditUseCase;
    private final Clock clock;

    @Override
    @Transactional(readOnly = true)
    public Result introspect(Command cmd) {
        Result result = lookup(cmd);
        recordAudit(cmd, result);
        return result;
    }

    private Result lookup(Command cmd) {
        // hint 가 refresh 면 refresh 부터, 그 외는 access 부터.
        if (HINT_REFRESH.equals(cmd.tokenTypeHint())) {
            return introspectRefresh(cmd.token())
                    .or(() -> introspectAccess(cmd.token()))
                    .orElse(Result.inactive());
        }
        return introspectAccess(cmd.token())
                .or(() -> introspectRefresh(cmd.token()))
                .orElse(Result.inactive());
    }

    private Optional<Result> introspectAccess(String token) {
        Optional<AccessTokenIntrospector.Decoded> decoded = accessTokenIntrospector.decode(token);
        if (decoded.isEmpty()) return Optional.empty();
        AccessTokenIntrospector.Decoded d = decoded.get();
        Instant now = clock.instant();
        // 만료 / nbf 는 decoder 가 검증하지만 introspect 는 명시적으로 한 번 더 확인.
        if (d.expiresAt() != null && !now.isBefore(d.expiresAt())) {
            return Optional.of(Result.inactive());
        }
        if (d.jwtId() != null && accessTokenBlocklist.contains(d.jwtId())) {
            // 운영자 강제 revoke (RFC 7009) 결과가 즉시 반영되는 지점.
            return Optional.of(Result.inactive());
        }
        return Optional.of(new Result(
                true,
                TOKEN_TYPE_BEARER,
                joinScope(d.permissions()),
                d.audience(),
                null,
                d.subject(),
                d.tenantId(),
                d.roles() == null ? List.of() : d.roles(),
                d.issuedAt(),
                d.expiresAt(),
                d.issuedAt(),
                d.issuer(),
                d.jwtId(),
                Map.of()));
    }

    private Optional<Result> introspectRefresh(String token) {
        // refresh token 은 평문 형태가 자유롭지만, JWT 처럼 dot 두 개로 시작하면 access 일
        // 가능성이 더 높으므로 굳이 hash 조회까지 가지 않게 단축.
        if (looksLikeJwt(token)) return Optional.empty();
        String hash = TokenHasher.sha256(token);
        Optional<RefreshToken> found = refreshTokenRepository.findByTokenHashReadOnly(hash);
        if (found.isEmpty()) return Optional.empty();
        RefreshToken rt = found.get();
        Instant now = clock.instant();
        boolean active = rt.status() == RefreshTokenStatus.ACTIVE && now.isBefore(rt.expiresAt());
        if (!active) {
            return Optional.of(Result.inactive());
        }
        return Optional.of(new Result(
                true,
                "refresh",
                null,
                null,
                null,
                rt.userId().asString(),
                rt.tenantId().asString(),
                List.of(),
                rt.issuedAt(),
                rt.expiresAt(),
                rt.issuedAt(),
                null,
                rt.id().toString(),
                Map.of()));
    }

    private void recordAudit(Command cmd, Result result) {
        try {
            // active 여부와 token type / 호출자만 audit. 토큰 자체는 절대 적재 X.
            Map<String, String> payload = new LinkedHashMap<>();
            payload.put("active", Boolean.toString(result.active()));
            if (result.tokenType() != null) payload.put("tokenType", result.tokenType());
            if (cmd.tokenTypeHint() != null) payload.put("hint", cmd.tokenTypeHint());
            if (cmd.callerClient() != null) payload.put("client", cmd.callerClient());
            // active 면 누구의 토큰인지 audit 에는 남겨야 운영자가 이상 패턴 (특정 사용자에
            // 대한 introspect 폭증) 을 잡을 수 있음. inactive (가짜 토큰 / 외부 issuer) 은
            // 사용자 컨텍스트가 없으므로 nil UUID 로 표현.
            TenantId tenant = result.tenantId() != null
                    ? TenantId.of(result.tenantId())
                    : TenantId.of(NIL_UUID);
            UserId user = result.subject() != null ? UserId.of(result.subject()) : null;
            auditUseCase.record(
                    tenant, user, AuditEventType.TOKEN_INTROSPECTED,
                    null, null, payload);
        } catch (RuntimeException e) {
            // audit 실패가 introspection 응답을 막으면 안 됨.
            log.warn("token introspect audit 적재 실패 — 결과는 정상 반환", e);
        }
    }

    /** RFC 4122 의 nil UUID — "사용자 컨텍스트 없음" 을 audit 에 표현. */
    private static final java.util.UUID NIL_UUID = new java.util.UUID(0L, 0L);

    private static boolean looksLikeJwt(String token) {
        // 가장 단순한 휴리스틱 — JWT 는 base64url . base64url . base64url 형식.
        int firstDot = token.indexOf('.');
        if (firstDot <= 0) return false;
        int secondDot = token.indexOf('.', firstDot + 1);
        return secondDot > firstDot;
    }

    private static String joinScope(List<String> permissions) {
        if (permissions == null || permissions.isEmpty()) return null;
        return String.join(" ", permissions);
    }
}
