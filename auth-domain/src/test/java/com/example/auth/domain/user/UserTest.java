package com.example.auth.domain.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.domain.common.TenantId;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class UserTest {

    private static final String BCRYPT_LIKE_HASH =
            "$2a$12$abcdefghijklmnopqrstuvWXYZ0123456789ABCDEFGHIJKLMNopqr";
    private static final TenantId TENANT = TenantId.newId();
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void 가입_직후_사용자는_PENDING_VERIFICATION_상태이며_MFA_DISABLED() {
        User u = User.register(TENANT, "  Alice@example.com  ", BCRYPT_LIKE_HASH, NOW);

        assertThat(u.email()).isEqualTo("alice@example.com");
        assertThat(u.status()).isEqualTo(UserStatus.PENDING_VERIFICATION);
        assertThat(u.mfaStatus()).isEqualTo(MfaStatus.DISABLED);
        assertThat(u.canLogin()).isTrue();
        assertThat(u.requiresMfa()).isFalse();
    }

    @Test
    void 평문_비밀번호가_도메인에_들어오면_거부() {
        assertThatThrownBy(() ->
                        User.register(TENANT, "a@b.c", "short", NOW))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("hash");
    }

    @Test
    void toString_은_평문_email_을_노출하지_않는다() {
        User u = User.register(TENANT, "alice@example.com", BCRYPT_LIKE_HASH, NOW);

        String repr = u.toString();

        assertThat(repr).doesNotContain("alice@example.com");
        assertThat(repr).doesNotContain(BCRYPT_LIKE_HASH);
        assertThat(repr).contains("a***e@e***e.com");
    }

    @Test
    void 메일_인증을_거치면_ACTIVE_가_되고_재호출은_idempotent() {
        User u = User.register(TENANT, "a@b.c", BCRYPT_LIKE_HASH, NOW);
        User verified = u.markVerified(NOW.plusSeconds(60));
        User again = verified.markVerified(NOW.plusSeconds(120));

        assertThat(verified.status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(again.status()).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void LOCKED_사용자는_canLogin_이_false() {
        User u = User.register(TENANT, "a@b.c", BCRYPT_LIKE_HASH, NOW)
                .markVerified(NOW)
                .lock(NOW.plusSeconds(10));

        assertThat(u.canLogin()).isFalse();
    }

    @Test
    void enableMfa_후에는_requiresMfa_가_true() {
        User u = User.register(TENANT, "a@b.c", BCRYPT_LIKE_HASH, NOW)
                .markVerified(NOW)
                .enableMfa(NOW.plusSeconds(10));

        assertThat(u.requiresMfa()).isTrue();
    }
}
