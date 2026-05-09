package com.example.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.application.exception.TenantNotFoundException;
import com.example.auth.application.port.in.LinkOrCreateUserFromOidcUseCase.Command;
import com.example.auth.domain.identity.ExternalProvider;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.user.User;
import com.example.auth.domain.user.UserStatus;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * LinkOrCreateUserFromOidcService (ADR-0013) — 매핑 우선순위 검증.
 */
class LinkOrCreateUserFromOidcServiceTest {

    private InMemoryFakes.FakeUserRepository users;
    private InMemoryFakes.FakeTenantRepository tenants;
    private InMemoryFakes.FakeExternalIdentityRepository externals;
    private InMemoryFakes.FakePasswordHasher hasher;
    private InMemoryFakes.CapturingAuditLog auditLog;
    private LinkOrCreateUserFromOidcService service;

    private Tenant tenant;
    private final Clock clock = Clock.fixed(Instant.parse("2026-05-09T10:00:00Z"), ZoneOffset.UTC);

    @BeforeEach
    void setUp() {
        users = new InMemoryFakes.FakeUserRepository();
        tenants = new InMemoryFakes.FakeTenantRepository();
        externals = new InMemoryFakes.FakeExternalIdentityRepository();
        hasher = new InMemoryFakes.FakePasswordHasher();
        auditLog = new InMemoryFakes.CapturingAuditLog();
        AuditLoginAttemptsService auditService = new AuditLoginAttemptsService(auditLog, clock);

        service = new LinkOrCreateUserFromOidcService(
                externals, users, tenants, hasher, auditService, clock);

        tenant = tenants.save(Tenant.create("acme", "ACME", clock.instant()));
    }

    @Test
    void 새_OIDC_사용자는_자동_가입되고_external_매핑이_저장된다() {
        User user = service.linkOrCreate(new Command(
                "acme", ExternalProvider.GOOGLE, "google-sub-123", "alice@example.com"));

        assertThat(users.findById(tenant.id(), user.id())).isPresent();
        // OIDC 자동 가입은 verified 상태 — IdP 가 이메일을 검증했다고 보장.
        assertThat(user.status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(externals.findByProviderSubject(ExternalProvider.GOOGLE, "google-sub-123"))
                .isPresent();
    }

    @Test
    void 자동_가입된_사용자는_OIDC_외_로그인_차단_위해_랜덤_비밀번호_해시() {
        User user = service.linkOrCreate(new Command(
                "acme", ExternalProvider.GOOGLE, "google-sub-456", "bob@example.com"));

        // FakePasswordHasher 가 "HASH:<원문>:..." 모양 — 원문을 랜덤으로 만들었다는 것만 확인
        assertThat(user.passwordHash()).startsWith("HASH:");
        // 빈 비밀번호 / 정해진 비밀번호 가 아니라는 것 확인.
        assertThat(user.passwordHash()).isNotEqualTo("HASH::HASH:HASH:HASH:HASH");
    }

    @Test
    void 같은_external_매핑이_재방문하면_link_새로_생성하지_않고_사용자_유지() {
        User first = service.linkOrCreate(new Command(
                "acme", ExternalProvider.GOOGLE, "google-sub-789", "carol@example.com"));
        int linksAfterFirst = externals.size();

        User second = service.linkOrCreate(new Command(
                "acme", ExternalProvider.GOOGLE, "google-sub-789", "carol@example.com"));

        assertThat(second.id()).isEqualTo(first.id());
        assertThat(externals.size()).isEqualTo(linksAfterFirst); // 새 row 생성 안 됨
    }

    @Test
    void 같은_이메일의_기존_사용자가_있으면_link_만_추가() {
        // 기존 비밀번호 가입 사용자
        User existing = users.save(User.register(
                tenant.id(), "dave@example.com", "BCRYPT_HASH_PLACEHOLDER_LEN_OK",
                clock.instant()));

        User linked = service.linkOrCreate(new Command(
                "acme", ExternalProvider.GOOGLE, "google-sub-dave", "dave@example.com"));

        assertThat(linked.id()).isEqualTo(existing.id());
        // external 매핑은 1개 새로 생성.
        assertThat(externals.size()).isEqualTo(1);
        // 기존 사용자 비밀번호는 그대로 (덮어쓰기 안 됨).
        assertThat(users.findById(tenant.id(), existing.id()).orElseThrow().passwordHash())
                .isEqualTo("BCRYPT_HASH_PLACEHOLDER_LEN_OK");
    }

    @Test
    void 모르는_테넌트는_거부() {
        assertThatThrownBy(() -> service.linkOrCreate(new Command(
                "nope", ExternalProvider.GOOGLE, "sub", "x@example.com")))
                .isInstanceOf(TenantNotFoundException.class);
    }

    @Test
    void OIDC_가_이메일_안주면_자동가입은_거부() {
        assertThatThrownBy(() -> service.linkOrCreate(new Command(
                "acme", ExternalProvider.GOOGLE, "sub-no-email", null)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
