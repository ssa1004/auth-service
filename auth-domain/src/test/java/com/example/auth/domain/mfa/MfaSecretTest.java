package com.example.auth.domain.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.domain.common.UserId;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class MfaSecretTest {

    private static final UserId USER = UserId.newId();
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final String CIPHER = "AES_GCM_BASE64==:somethinglooooooooong";

    @Test
    void enroll_직후는_미확인_상태() {
        MfaSecret s = MfaSecret.enroll(USER, CIPHER, MfaMethod.TOTP, NOW);

        assertThat(s.isConfirmed()).isFalse();
        assertThat(s.confirmedAt()).isNull();
    }

    @Test
    void confirm_후에는_isConfirmed_가_true() {
        MfaSecret s = MfaSecret.enroll(USER, CIPHER, MfaMethod.TOTP, NOW)
                .confirm(NOW.plusSeconds(30));

        assertThat(s.isConfirmed()).isTrue();
    }

    @Test
    void 평문이거나_짧은_secret_은_거부() {
        assertThatThrownBy(() -> MfaSecret.enroll(USER, "short", MfaMethod.TOTP, NOW))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void toString_은_secretCipher_를_노출하지_않는다() {
        MfaSecret s = MfaSecret.enroll(USER, CIPHER, MfaMethod.TOTP, NOW);

        assertThat(s.toString()).doesNotContain(CIPHER);
    }
}
