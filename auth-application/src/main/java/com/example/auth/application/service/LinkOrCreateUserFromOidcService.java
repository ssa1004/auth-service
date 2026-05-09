package com.example.auth.application.service;

import com.example.auth.application.exception.TenantNotFoundException;
import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.in.LinkOrCreateUserFromOidcUseCase;
import com.example.auth.application.port.out.ExternalIdentityRepository;
import com.example.auth.application.port.out.PasswordHasher;
import com.example.auth.application.port.out.TenantRepository;
import com.example.auth.application.port.out.UserRepository;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.EmailMasker;
import com.example.auth.domain.identity.ExternalIdentity;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.user.User;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * OIDC callback 처리 (ADR-0013).
 *
 * <p>매핑 우선순위:
 * <ol>
 *   <li>{@code (provider, providerUserId)} 로 기존 외부 매핑 조회 → user 그대로 사용 (last_login_at 갱신).</li>
 *   <li>같은 테넌트의 같은 이메일 사용자가 있으면 link — 외부 매핑만 추가하고 기존 user 사용.</li>
 *   <li>아무 매핑 / 사용자 없음 → 자동 가입 — 비밀번호는 랜덤 (사용자가 OIDC 로만 로그인).
 *       이후 로컬 비밀번호 로그인을 원하면 비밀번호 재설정 흐름.</li>
 * </ol>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LinkOrCreateUserFromOidcService implements LinkOrCreateUserFromOidcUseCase {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final ExternalIdentityRepository externalIdentityRepository;
    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final PasswordHasher passwordHasher;
    private final AuditLoginAttemptsUseCase auditUseCase;
    private final Clock clock;

    @Override
    @Transactional
    public User linkOrCreate(Command cmd) {
        Tenant tenant = tenantRepository.findBySlug(cmd.tenantSlug())
                .orElseThrow(() -> new TenantNotFoundException(cmd.tenantSlug()));
        if (!tenant.isActive()) {
            throw new TenantNotFoundException(cmd.tenantSlug());
        }
        String email = cmd.email() == null ? null : cmd.email().toLowerCase().trim();

        // 1. 외부 매핑 우선.
        var existing = externalIdentityRepository.findByProviderSubject(
                cmd.provider(), cmd.providerUserId());
        if (existing.isPresent()) {
            ExternalIdentity touched = existing.get().touchLogin(clock.instant());
            externalIdentityRepository.save(touched);
            User user = userRepository.findById(tenant.id(), touched.userId())
                    .orElseThrow(() -> new IllegalStateException(
                            "external_identities.user_id 가 사용자 도메인에 없음 — 데이터 무결성 사고"));
            audit(tenant.id(), user, cmd.provider(), email, "EXISTING_LINK");
            return user;
        }

        // 2. 같은 테넌트의 같은 이메일 사용자에 link.
        if (email != null) {
            var byEmail = userRepository.findByEmail(tenant.id(), email);
            if (byEmail.isPresent()) {
                User user = byEmail.get();
                ExternalIdentity link = ExternalIdentity.link(
                        user.id(), cmd.provider(), cmd.providerUserId(), email, clock.instant());
                externalIdentityRepository.save(link);
                audit(tenant.id(), user, cmd.provider(), email, "LINKED_TO_EXISTING_USER");
                log.info("OIDC link 기존 사용자 tenant={} provider={} user={}",
                        tenant.slug(), cmd.provider(), user.id().asString());
                return user;
            }
        }

        // 3. 자동 가입 — 비밀번호는 랜덤 32 byte (OIDC 외 로그인 차단). 사용자가 비밀번호 로그인을
        // 원하면 비밀번호 재설정 흐름으로 자신의 비밀번호를 새로 설정합니다.
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("OIDC 사용자 자동 가입에는 이메일이 필요합니다");
        }
        String randomSecret = base64Random(32);
        String passwordHash = passwordHasher.hash(randomSecret);
        User newUser = User.register(tenant.id(), email, passwordHash, clock.instant())
                .markVerified(clock.instant());
        User saved = userRepository.save(newUser);

        ExternalIdentity link = ExternalIdentity.link(
                saved.id(), cmd.provider(), cmd.providerUserId(), email, clock.instant());
        externalIdentityRepository.save(link);

        audit(tenant.id(), saved, cmd.provider(), email, "AUTO_REGISTERED");
        log.info("OIDC 자동 가입 tenant={} provider={} user={} email={}",
                tenant.slug(), cmd.provider(), saved.id().asString(), EmailMasker.mask(email));
        return saved;
    }

    private void audit(com.example.auth.domain.common.TenantId tenantId,
                       User user,
                       com.example.auth.domain.identity.ExternalProvider provider,
                       String email,
                       String result) {
        auditUseCase.record(
                tenantId,
                user.id(),
                AuditEventType.USER_REGISTERED, // 본 단계는 별도 OIDC_LINKED 타입 추가 미보류
                null, // ip / userAgent 는 controller 단에서 채워서 보내는 것이 깔끔하지만 본 skeleton 은 단순화
                null,
                Map.of(
                        "oidcProvider", provider.name(),
                        "oidcResult", result,
                        "emailMasked", email == null ? "null" : EmailMasker.mask(email)));
    }

    private static String base64Random(int byteLen) {
        byte[] bytes = new byte[byteLen];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
