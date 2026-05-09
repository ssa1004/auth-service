package com.example.auth.application.service;

import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.exception.MfaRequiredException;
import com.example.auth.application.exception.RateLimitedException;
import com.example.auth.application.exception.TenantNotFoundException;
import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.in.LoginUseCase;
import com.example.auth.application.port.out.MfaChallengeStore;
import com.example.auth.application.port.out.PasswordHasher;
import com.example.auth.application.port.out.RateLimiter;
import com.example.auth.application.port.out.TenantRepository;
import com.example.auth.application.port.out.UserRepository;
import com.example.auth.application.security.AuthProperties;
import com.example.auth.application.security.AuthTokens;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.EmailMasker;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.user.User;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginService implements LoginUseCase {

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final PasswordHasher passwordHasher;
    private final RateLimiter rateLimiter;
    private final MfaChallengeStore mfaChallengeStore;
    private final SessionIssuer sessionIssuer;
    private final AuditLoginAttemptsUseCase auditUseCase;
    private final AuthProperties properties;

    @Override
    @Transactional
    public AuthTokens login(Command cmd) {
        Tenant tenant = tenantRepository.findBySlug(cmd.tenantSlug())
                .orElseThrow(() -> new TenantNotFoundException(cmd.tenantSlug()));
        String email = cmd.email().toLowerCase().trim();
        String rateKey = "login:" + tenant.slug() + ":" + cmd.ipAddress() + ":" + email;
        if (!rateLimiter.tryConsume(rateKey)) {
            auditUseCase.record(
                    tenant.id(), null, AuditEventType.LOGIN_FAILED_RATE_LIMITED,
                    cmd.ipAddress(), cmd.userAgent(),
                    Map.of("email", EmailMasker.mask(email)));
            throw new RateLimitedException();
        }

        Optional<User> userOpt = userRepository.findByEmail(tenant.id(), email);
        if (userOpt.isEmpty()) {
            // 사용자 미존재여도 *bad credentials* 와 동일한 응답 (정보 누설 방지).
            auditUseCase.record(
                    tenant.id(), null, AuditEventType.LOGIN_FAILED_BAD_CREDENTIALS,
                    cmd.ipAddress(), cmd.userAgent(),
                    Map.of("email", EmailMasker.mask(email), "reason", "user_not_found"));
            throw new InvalidCredentialsException();
        }
        User user = userOpt.get();
        if (!user.canLogin()) {
            auditUseCase.record(
                    tenant.id(), user.id(), AuditEventType.LOGIN_FAILED_USER_LOCKED,
                    cmd.ipAddress(), cmd.userAgent(),
                    Map.of("email", EmailMasker.mask(email), "status", user.status().name()));
            throw new InvalidCredentialsException();
        }
        if (!passwordHasher.matches(cmd.rawPassword(), user.passwordHash())) {
            auditUseCase.record(
                    tenant.id(), user.id(), AuditEventType.LOGIN_FAILED_BAD_CREDENTIALS,
                    cmd.ipAddress(), cmd.userAgent(),
                    Map.of("email", EmailMasker.mask(email), "reason", "password_mismatch"));
            throw new InvalidCredentialsException();
        }

        if (user.requiresMfa()) {
            String challenge = mfaChallengeStore.issueChallenge(tenant.id(), user.id(), Duration.ofMinutes(5));
            auditUseCase.record(
                    tenant.id(), user.id(), AuditEventType.MFA_REQUIRED,
                    cmd.ipAddress(), cmd.userAgent(),
                    Map.of("email", EmailMasker.mask(email)));
            throw new MfaRequiredException(challenge);
        }

        AuthTokens tokens = sessionIssuer.issue(
                tenant, user, Set.of("pwd"), cmd.ipAddress(), cmd.userAgent(), cmd.deviceLabel());
        auditUseCase.record(
                tenant.id(), user.id(), AuditEventType.LOGIN_SUCCEEDED,
                cmd.ipAddress(), cmd.userAgent(),
                Map.of("email", EmailMasker.mask(email)));
        return tokens;
    }
}
