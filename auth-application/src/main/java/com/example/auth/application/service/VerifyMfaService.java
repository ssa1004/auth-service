package com.example.auth.application.service;

import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.in.VerifyMfaUseCase;
import com.example.auth.application.port.out.MfaChallengeStore;
import com.example.auth.application.port.out.MfaSecretCipher;
import com.example.auth.application.port.out.MfaSecretRepository;
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
    private final SessionIssuer sessionIssuer;
    private final AuditLoginAttemptsUseCase auditUseCase;

    @Override
    @Transactional
    public AuthTokens verify(Command cmd) {
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
