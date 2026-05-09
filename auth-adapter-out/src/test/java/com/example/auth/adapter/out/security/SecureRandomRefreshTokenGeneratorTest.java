package com.example.auth.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SecureRandomRefreshTokenGeneratorTest {

    @Test
    void 생성된_token_은_url_safe_충분한_엔트로피_그리고_매번_다르다() {
        var gen = new SecureRandomRefreshTokenGenerator();

        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            String t = gen.generate();
            assertThat(t).matches("[A-Za-z0-9_-]+");
            assertThat(t.length()).isGreaterThanOrEqualTo(43); // 32 bytes base64url
            seen.add(t);
        }
        // 충돌 확률 ~ 0
        assertThat(seen).hasSize(1000);
    }
}
