package com.example.auth.application.service;

import com.example.auth.application.exception.RateLimitedException;
import com.example.auth.application.exception.TenantNotFoundException;
import com.example.auth.application.exception.UserAlreadyExistsException;
import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.in.RegisterUserUseCase;
import com.example.auth.application.port.out.PasswordHasher;
import com.example.auth.application.port.out.RateLimiter;
import com.example.auth.application.port.out.TenantRepository;
import com.example.auth.application.port.out.UserRepository;
import com.example.auth.application.port.out.VerificationMailSender;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.EmailMasker;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.user.User;
import java.time.Clock;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RegisterUserService implements RegisterUserUseCase {

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final PasswordHasher passwordHasher;
    private final VerificationMailSender mailSender;
    private final RateLimiter rateLimiter;
    private final AuditLoginAttemptsUseCase auditUseCase;
    private final Clock clock;

    @Override
    @Transactional
    public UserId register(Command cmd) {
        Tenant tenant = tenantRepository.findBySlug(cmd.tenantSlug())
                .orElseThrow(() -> new TenantNotFoundException(cmd.tenantSlug()));
        if (!tenant.isActive()) {
            throw new TenantNotFoundException(cmd.tenantSlug());
        }
        // OWASP API4 / API6 — register 는 인증 없이 호출되므로 IP 별 token bucket 으로
        // 자동 가입 / 계정 enumeration (409 응답을 oracle 로 활용) 을 차단합니다. login 과
        // 같은 bucket 설정 (10 req/min) 을 별도 키로 사용 — 사용자 합법 가입 흐름은 영향 X.
        if (cmd.ipAddress() != null) {
            String rateKey = "register:" + tenant.slug() + ":" + cmd.ipAddress();
            if (!rateLimiter.tryConsume(rateKey)) {
                throw new RateLimitedException();
            }
        }
        String email = cmd.email().toLowerCase().trim();
        if (userRepository.existsByEmail(tenant.id(), email)) {
            throw new UserAlreadyExistsException();
        }
        String hash = passwordHasher.hash(cmd.rawPassword());
        User user = User.register(tenant.id(), email, hash, clock.instant());
        User saved = userRepository.save(user);

        // 메일 발송 — 운영에서는 verification token + signed link 가 들어가지만 본 단계에서는
        // mock 으로 충분. 평문 비밀번호는 메일에도 절대 들어가면 안 됩니다.
        mailSender.sendVerification(email, "https://auth.example.com/verify?token=...");

        auditUseCase.record(
                tenant.id(),
                saved.id(),
                AuditEventType.USER_REGISTERED,
                null,
                null,
                Map.of("email", EmailMasker.mask(email)));

        log.info("user registered tenant={} user={} email={}",
                tenant.slug(), saved.id().asString(), EmailMasker.mask(email));
        return saved.id();
    }
}
