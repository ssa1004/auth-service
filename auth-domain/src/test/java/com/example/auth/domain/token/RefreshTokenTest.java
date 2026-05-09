package com.example.auth.domain.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class RefreshTokenTest {

    private static final TenantId TENANT = TenantId.newId();
    private static final UserId USER = UserId.newId();
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final String HASH = TokenHasher.sha256("super-secret-random-token-from-csprng");

    @Test
    void 평문_token_을_도메인에_넣으면_거부() {
        assertThatThrownBy(() -> RefreshToken.issue(
                TENANT, USER, "short", null, "macbook", "1.2.3.4",
                NOW, NOW.plus(Duration.ofDays(30))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 발급_직후는_ACTIVE_이며_isUsable() {
        RefreshToken rt = RefreshToken.issue(
                TENANT, USER, HASH, null, "macbook", "1.2.3.4",
                NOW, NOW.plus(Duration.ofDays(30)));

        assertThat(rt.status()).isEqualTo(RefreshTokenStatus.ACTIVE);
        assertThat(rt.isUsable(NOW.plusSeconds(60))).isTrue();
    }

    @Test
    void 만료된_토큰은_isUsable_이_false() {
        RefreshToken rt = RefreshToken.issue(
                TENANT, USER, HASH, null, "macbook", "1.2.3.4",
                NOW, NOW.plus(Duration.ofMinutes(1)));

        assertThat(rt.isUsable(NOW.plus(Duration.ofMinutes(2)))).isFalse();
    }

    @Test
    void 회전된_토큰이_다시_들어오면_reuse_signal() {
        RefreshToken rt = RefreshToken.issue(
                TENANT, USER, HASH, null, "macbook", "1.2.3.4",
                NOW, NOW.plus(Duration.ofDays(30)));
        RefreshToken rotated = rt.markRotated(NOW.plusSeconds(10));

        assertThat(rotated.isUsable(NOW.plusSeconds(20))).isFalse();
        assertThat(rotated.isReuseSignal()).isTrue();
    }

    @Test
    void 사용자_revoke_와_reuse_revoke_는_상태가_구분된다() {
        RefreshToken rt = RefreshToken.issue(
                TENANT, USER, HASH, null, "macbook", "1.2.3.4",
                NOW, NOW.plus(Duration.ofDays(30)));

        assertThat(rt.markRevokedByUser(NOW).status())
                .isEqualTo(RefreshTokenStatus.REVOKED_BY_USER);
        assertThat(rt.markRevokedReuseDetected(NOW).status())
                .isEqualTo(RefreshTokenStatus.REVOKED_REUSE_DETECTED);
    }

    @Test
    void toString_은_tokenHash_를_노출하지_않는다() {
        RefreshToken rt = RefreshToken.issue(
                TENANT, USER, HASH, null, "macbook", "1.2.3.4",
                NOW, NOW.plus(Duration.ofDays(30)));

        assertThat(rt.toString()).doesNotContain(HASH);
    }
}
