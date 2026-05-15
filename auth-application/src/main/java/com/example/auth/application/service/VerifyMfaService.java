package com.example.auth.application.service;

import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.exception.RateLimitedException;
import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.in.VerifyMfaUseCase;
import com.example.auth.application.port.out.MfaChallengeStore;
import com.example.auth.application.port.out.MfaSecretCipher;
import com.example.auth.application.port.out.MfaSecretRepository;
import com.example.auth.application.port.out.RateLimiter;
import com.example.auth.application.port.out.TenantRepository;
import com.example.auth.application.port.out.TotpVerifier;
import com.example.auth.application.port.out.UserRepository;
import com.example.auth.application.security.AuthTokens;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.mfa.MfaSecret;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.user.User;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class VerifyMfaService implements VerifyMfaUseCase {

    private final MfaChallengeStore mfaChallengeStore;
    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final MfaSecretRepository mfaSecretRepository;
    private final MfaSecretCipher mfaSecretCipher;
    private final TotpVerifier totpVerifier;
    private final RateLimiter rateLimiter;
    private final SessionIssuer sessionIssuer;
    private final AuditLoginAttemptsUseCase auditUseCase;

    @Override
    @Transactional
    public AuthTokens verify(Command cmd) {
        // OWASP API4 — verify-mfa 도 인증 없이 호출되는 endpoint. 6자리 TOTP 는 공간이
        // 좁아 (10^6) re-login → mfaToken 재발급 → 추측 루프로 brute-force 가 가능합니다.
        // login / register / refresh 와 같은 IP 별 token bucket 으로 추측 속도를 직접 제한
        // — login bucket 에 간접적으로 기대지 않고 endpoint 자체에 가드를 둡니다. ip 가 null
        // 인 단위 테스트 경로는 우회 (e2e / 운영은 ClientIpResolver 가 항상 채움).
        if (cmd.ipAddress() != null) {
            String rateKey = "verify-mfa:" + cmd.ipAddress();
            if (!rateLimiter.tryConsume(rateKey)) {
                throw new RateLimitedException();
            }
        }
        var challenge = mfaChallengeStore.consume(cmd.mfaChallengeToken())
                .orElseThrow(InvalidCredentialsException::new);
        UserId userId = challenge.userId();
        Tenant tenant = tenantRepository.findById(challenge.tenantId())
                .orElseThrow(InvalidCredentialsException::new);
        User user = userRepository.findById(tenant.id(), userId)
                .orElseThrow(InvalidCredentialsException::new);

        MfaSecret secret = mfaSecretRepository.findByUser(userId)
                .orElseThrow(InvalidCredentialsException::new);
        // 평문 secret 은 검증 직전에만 잠시 풀고, verify 호출 후 변수 범위를 벗어나면 GC 대상.
        String plaintext = mfaSecretCipher.decrypt(secret.secretCipher());
        boolean ok = totpVerifier.verify(plaintext, cmd.code());
        if (!ok) {
            auditUseCase.record(
                    tenant.id(), userId, AuditEventType.MFA_FAILED,
                    cmd.ipAddress(), cmd.userAgent(), Map.of());
            throw new InvalidCredentialsException();
        }

        AuthTokens tokens = sessionIssuer.issue(
                tenant, user, Set.of("pwd", "mfa"), cmd.ipAddress(), cmd.userAgent(), cmd.deviceLabel());
        auditUseCase.record(
                tenant.id(), userId, AuditEventType.MFA_VERIFIED,
                cmd.ipAddress(), cmd.userAgent(), Map.of());
        return tokens;
    }
}
