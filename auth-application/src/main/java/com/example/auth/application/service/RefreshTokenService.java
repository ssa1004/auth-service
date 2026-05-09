package com.example.auth.application.service;

import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.exception.RefreshReuseDetectedException;
import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.in.RefreshTokenUseCase;
import com.example.auth.application.port.out.RefreshTokenRepository;
import com.example.auth.application.port.out.TenantRepository;
import com.example.auth.application.port.out.UserRepository;
import com.example.auth.application.security.AuthTokens;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.token.RefreshToken;
import com.example.auth.domain.token.TokenHasher;
import com.example.auth.domain.user.User;
import java.time.Clock;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Refresh token rotation + reuse detection (Auth0 패턴, ADR-0004).
 *
 * <ol>
 *   <li>요청된 평문 token 을 hash → DB lookup</li>
 *   <li>찾은 토큰이 ACTIVE 면 → 회전 발급 (parent 로 연결)</li>
 *   <li>찾은 토큰이 ROTATED 면 → reuse 신호. 사용자의 모든 refresh 일괄 revoke + 401</li>
 *   <li>그 외 (REVOKED_BY_USER / EXPIRED 등) → 401</li>
 * </ol>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService implements RefreshTokenUseCase {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final SessionIssuer sessionIssuer;
    private final AuditLoginAttemptsUseCase auditUseCase;
    private final Clock clock;

    @Override
    @Transactional
    public AuthTokens refresh(Command cmd) {
        String hash = TokenHasher.sha256(cmd.refreshTokenPlain());
        RefreshToken existing = refreshTokenRepository.findByTokenHash(hash)
                .orElseThrow(InvalidCredentialsException::new);

        if (existing.isReuseSignal()) {
            // 이미 정상 회전된 token 이 다시 들어옴 — 탈취 의심.
            int revoked = refreshTokenRepository.revokeAllForUser(existing.tenantId(), existing.userId());
            auditUseCase.record(
                    existing.tenantId(), existing.userId(),
                    AuditEventType.REFRESH_REUSE_DETECTED,
                    cmd.ipAddress(), cmd.userAgent(),
                    Map.of("revokedSessions", String.valueOf(revoked)));
            log.warn("refresh reuse detected user={} revoked={}",
                    existing.userId().asString(), revoked);
            throw new RefreshReuseDetectedException();
        }

        if (!existing.isUsable(clock.instant())) {
            // EXPIRED / REVOKED_BY_USER / REVOKED_REUSE_DETECTED — 모두 invalid 처리.
            throw new InvalidCredentialsException();
        }

        Tenant tenant = tenantRepository.findById(existing.tenantId())
                .orElseThrow(InvalidCredentialsException::new);
        User user = userRepository.findById(tenant.id(), existing.userId())
                .orElseThrow(InvalidCredentialsException::new);
        if (!user.canLogin()) {
            throw new InvalidCredentialsException();
        }

        // 1) 기존 token 을 ROTATED 로 마킹 (재사용 시 이게 reuse signal 로 잡힘)
        refreshTokenRepository.save(existing.markRotated(clock.instant()));
        // 2) 새 access + refresh 발급. parent = existing.id 로 연결 (audit 추적용).
        Set<String> amr = user.requiresMfa() ? Set.of("pwd", "mfa") : Set.of("pwd");
        AuthTokens tokens = sessionIssuer.issue(
                tenant, user, amr,
                cmd.ipAddress(), cmd.userAgent(), existing.deviceLabel(),
                existing.id());
        auditUseCase.record(
                tenant.id(), user.id(), AuditEventType.REFRESH_ROTATED,
                cmd.ipAddress(), cmd.userAgent(),
                Map.of("parentSession", existing.id().toString()));
        return tokens;
    }
}
