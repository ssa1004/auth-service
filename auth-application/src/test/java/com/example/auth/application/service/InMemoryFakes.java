package com.example.auth.application.service;

import com.example.auth.application.authz.PolicyDecisionPort;
import com.example.auth.application.authz.PolicyDecisionRequest;
import com.example.auth.application.authz.PolicyDecisionResult;
import com.example.auth.application.port.out.AccessTokenIssuer;
import com.example.auth.application.port.out.AuditLogRepository;
import com.example.auth.application.port.out.ExternalIdentityRepository;
import com.example.auth.application.port.out.MfaChallengeStore;
import com.example.auth.application.port.out.MfaSecretCipher;
import com.example.auth.application.port.out.MfaSecretRepository;
import com.example.auth.application.port.out.PasswordHasher;
import com.example.auth.application.port.out.RateLimiter;
import com.example.auth.application.port.out.RefreshTokenGenerator;
import com.example.auth.application.port.out.RefreshTokenRepository;
import com.example.auth.application.port.out.RoleRepository;
import com.example.auth.application.port.out.TenantRepository;
import com.example.auth.application.port.out.TotpVerifier;
import com.example.auth.application.port.out.UserRepository;
import com.example.auth.application.port.out.VerificationMailSender;
import com.example.auth.application.security.AccessTokenClaims;
import com.example.auth.domain.audit.AuditEvent;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.identity.ExternalIdentity;
import com.example.auth.domain.identity.ExternalProvider;
import com.example.auth.domain.mfa.MfaSecret;
import com.example.auth.domain.role.Role;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.token.RefreshToken;
import com.example.auth.domain.user.User;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 단위 테스트용 in-memory 구현체 모음. 각 service 의 동작을 외부 의존성 없이 검증하기 위해
 * 사용. 실제 Spring 빈 등록은 절대 사용하지 않습니다 — `@MockBean` 도 아닌 순수 객체.
 */
public final class InMemoryFakes {

    public static class FakeUserRepository implements UserRepository {
        private final Map<UUID, User> store = new ConcurrentHashMap<>();

        @Override
        public User save(User user) {
            store.put(user.id().value(), user);
            return user;
        }

        @Override
        public Optional<User> findById(TenantId tenantId, UserId id) {
            return Optional.ofNullable(store.get(id.value()))
                    .filter(u -> u.tenantId().equals(tenantId));
        }

        @Override
        public Optional<User> findByEmail(TenantId tenantId, String email) {
            return store.values().stream()
                    .filter(u -> u.tenantId().equals(tenantId) && u.email().equalsIgnoreCase(email))
                    .findFirst();
        }

        @Override
        public boolean existsByEmail(TenantId tenantId, String email) {
            return findByEmail(tenantId, email).isPresent();
        }
    }

    public static class FakeTenantRepository implements TenantRepository {
        private final Map<UUID, Tenant> store = new ConcurrentHashMap<>();

        @Override
        public Tenant save(Tenant tenant) {
            store.put(tenant.id().value(), tenant);
            return tenant;
        }

        @Override
        public Optional<Tenant> findById(TenantId id) {
            return Optional.ofNullable(store.get(id.value()));
        }

        @Override
        public Optional<Tenant> findBySlug(String slug) {
            return store.values().stream().filter(t -> t.slug().equals(slug)).findFirst();
        }
    }

    public static class FakeRoleRepository implements RoleRepository {
        private final Map<UUID, Role> roles = new ConcurrentHashMap<>();
        private final Map<UUID, java.util.Set<UUID>> userRoles = new ConcurrentHashMap<>();

        @Override
        public Role save(Role role) {
            roles.put(role.id(), role);
            return role;
        }

        @Override
        public Optional<Role> findById(TenantId tenantId, UUID roleId) {
            return Optional.ofNullable(roles.get(roleId)).filter(r -> r.tenantId().equals(tenantId));
        }

        @Override
        public Optional<Role> findBySlug(TenantId tenantId, String slug) {
            return roles.values().stream()
                    .filter(r -> r.tenantId().equals(tenantId) && r.slug().equals(slug))
                    .findFirst();
        }

        @Override
        public List<Role> findByUser(TenantId tenantId, UserId userId) {
            return userRoles.getOrDefault(userId.value(), java.util.Set.of()).stream()
                    .map(roles::get)
                    .filter(r -> r != null && r.tenantId().equals(tenantId))
                    .toList();
        }

        @Override
        public void assignToUser(TenantId tenantId, UserId userId, UUID roleId) {
            userRoles.computeIfAbsent(userId.value(), k -> ConcurrentHashMap.newKeySet()).add(roleId);
        }

        @Override
        public void revokeFromUser(TenantId tenantId, UserId userId, UUID roleId) {
            var set = userRoles.get(userId.value());
            if (set != null) set.remove(roleId);
        }
    }

    public static class FakeRefreshTokenRepository implements RefreshTokenRepository {
        private final Map<UUID, RefreshToken> store = new ConcurrentHashMap<>();

        @Override
        public RefreshToken save(RefreshToken token) {
            store.put(token.id(), token);
            return token;
        }

        @Override
        public Optional<RefreshToken> findByTokenHash(String tokenHash) {
            return store.values().stream().filter(t -> t.tokenHash().equals(tokenHash)).findFirst();
        }

        @Override
        public Optional<RefreshToken> findByTokenHashReadOnly(String tokenHash) {
            return findByTokenHash(tokenHash);
        }

        @Override
        public List<RefreshToken> findActiveByUser(TenantId tenantId, UserId userId) {
            return store.values().stream()
                    .filter(t -> t.tenantId().equals(tenantId) && t.userId().equals(userId))
                    .filter(t -> t.status() == com.example.auth.domain.token.RefreshTokenStatus.ACTIVE)
                    .toList();
        }

        @Override
        public int revokeAllForUser(TenantId tenantId, UserId userId) {
            var now = java.time.Instant.now();
            int n = 0;
            for (var t : new ArrayList<>(store.values())) {
                if (!t.tenantId().equals(tenantId) || !t.userId().equals(userId)) continue;
                if (t.status() == com.example.auth.domain.token.RefreshTokenStatus.REVOKED_REUSE_DETECTED) continue;
                if (t.status() == com.example.auth.domain.token.RefreshTokenStatus.REVOKED_BY_USER) continue;
                if (t.status() == com.example.auth.domain.token.RefreshTokenStatus.REVOKED_BY_ADMIN) continue;
                store.put(t.id(), t.markRevokedReuseDetected(now));
                n++;
            }
            return n;
        }

        public int size() { return store.size(); }
        public java.util.Collection<RefreshToken> all() { return Collections.unmodifiableCollection(store.values()); }
    }

    public static class FakeExternalIdentityRepository implements ExternalIdentityRepository {
        private final Map<UUID, ExternalIdentity> store = new ConcurrentHashMap<>();

        @Override
        public Optional<ExternalIdentity> findByProviderSubject(
                ExternalProvider provider, String providerUserId) {
            return store.values().stream()
                    .filter(i -> i.provider() == provider && i.providerUserId().equals(providerUserId))
                    .findFirst();
        }

        @Override
        public ExternalIdentity save(ExternalIdentity identity) {
            store.put(identity.id(), identity);
            return identity;
        }

        public int size() { return store.size(); }
    }

    public static class FakeMfaSecretRepository implements MfaSecretRepository {
        private final Map<UUID, MfaSecret> store = new ConcurrentHashMap<>();

        @Override
        public MfaSecret save(MfaSecret secret) {
            store.put(secret.userId().value(), secret);
            return secret;
        }

        @Override
        public Optional<MfaSecret> findByUser(UserId userId) {
            return Optional.ofNullable(store.get(userId.value()));
        }

        @Override
        public void deleteByUser(UserId userId) {
            store.remove(userId.value());
        }
    }

    public static class CapturingAuditLog implements AuditLogRepository {
        private final List<AuditEvent> events = Collections.synchronizedList(new ArrayList<>());

        @Override
        public AuditEvent append(AuditEvent event) {
            events.add(event);
            return event;
        }

        public List<AuditEvent> events() {
            return List.copyOf(events);
        }
    }

    /** BCrypt 대신 prefix "HASH:" 만 붙여 빠르게 비교. cost 정책은 단위 테스트 범위 밖. */
    public static class FakePasswordHasher implements PasswordHasher {
        @Override
        public String hash(String rawPassword) {
            return "HASH:" + rawPassword + ":HASH:HASH:HASH:HASH"; // 길이 가드 통과
        }

        @Override
        public boolean matches(String rawPassword, String hash) {
            return hash.equals(hash(rawPassword));
        }
    }

    public static class CountingMailSender implements VerificationMailSender {
        private final AtomicInteger n = new AtomicInteger();

        @Override
        public void sendVerification(String email, String verificationLink) {
            n.incrementAndGet();
        }

        public int sentCount() { return n.get(); }
    }

    public static class AlwaysAllowRateLimiter implements RateLimiter {
        @Override
        public boolean tryConsume(String key) {
            return true;
        }
    }

    public static class FixedDenyRateLimiter implements RateLimiter {
        @Override
        public boolean tryConsume(String key) {
            return false;
        }
    }

    public static class StubAccessTokenIssuer implements AccessTokenIssuer {
        public AccessTokenClaims lastClaims;

        @Override
        public String issue(AccessTokenClaims claims) {
            this.lastClaims = claims;
            // 평문 token 모양 — 테스트는 헤더/페이로드 파싱하지 않고 claims 자체를 검증.
            return "stub-jwt." + claims.userId().asString();
        }
    }

    public static class CountingRefreshTokenGenerator implements RefreshTokenGenerator {
        private final AtomicInteger n = new AtomicInteger();

        @Override
        public String generate() {
            return "rt-" + UUID.randomUUID() + "-" + n.incrementAndGet();
        }
    }

    public static class FakeMfaChallengeStore implements MfaChallengeStore {
        private final Map<String, Challenge> challenges = new ConcurrentHashMap<>();

        @Override
        public String issueChallenge(TenantId tenantId, UserId userId, Duration ttl) {
            String token = "mfa-" + UUID.randomUUID();
            challenges.put(token, new Challenge(tenantId, userId));
            return token;
        }

        @Override
        public Optional<Challenge> consume(String challengeToken) {
            return Optional.ofNullable(challenges.remove(challengeToken));
        }
    }

    public static class IdentityCipher implements MfaSecretCipher {
        @Override
        public String encrypt(String plaintextBase32Secret) {
            return "ENC:" + plaintextBase32Secret + ":ENC:ENC:ENC:ENC"; // 길이 가드 통과
        }

        @Override
        public String decrypt(String cipherText) {
            String prefix = "ENC:";
            String mid = cipherText.substring(prefix.length(), cipherText.indexOf(":ENC"));
            return mid;
        }
    }

    public static class StubTotpVerifier implements TotpVerifier {
        public String acceptCode = "123456";
        public String nextSecret = "JBSWY3DPEHPK3PXP";

        @Override
        public String generateSecret() {
            return nextSecret;
        }

        @Override
        public String otpAuthUrl(String label, String issuer, String secret) {
            return "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + issuer;
        }

        @Override
        public boolean verify(String secret, String code) {
            return acceptCode.equals(code);
        }
    }

    /**
     * 항상 allow 를 반환하는 정책 평가기. 개별 service 테스트에서 RBAC 흐름만 검증할 때
     * 사용. ABAC 동작 자체는 별도 테스트 (PolicyDecisionServiceTest) 가 검증.
     */
    public static class AlwaysAllowPolicyDecisionPort implements PolicyDecisionPort {
        public final List<String> calls = new ArrayList<>();

        @Override
        public PolicyDecisionResult evaluate(String policyPath, PolicyDecisionRequest request) {
            calls.add(policyPath + ":" + request.action());
            return PolicyDecisionResult.allowed();
        }
    }

    /** 항상 deny — 정책 거부 동작 검증용. */
    public static class AlwaysDenyPolicyDecisionPort implements PolicyDecisionPort {
        public final String reason;

        public AlwaysDenyPolicyDecisionPort(String reason) {
            this.reason = reason;
        }

        @Override
        public PolicyDecisionResult evaluate(String policyPath, PolicyDecisionRequest request) {
            return PolicyDecisionResult.denied(reason);
        }
    }

    public static Map<String, String> kv(String... entries) {
        if (entries.length % 2 != 0) throw new IllegalArgumentException();
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < entries.length; i += 2) m.put(entries[i], entries[i + 1]);
        return m;
    }

    public static java.util.Set<String> set(String... values) {
        return new LinkedHashSet<>(java.util.Arrays.asList(values));
    }
}
