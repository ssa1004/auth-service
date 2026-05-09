package com.example.auth.domain.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class TokenHasherTest {

    @Test
    void 같은_입력은_같은_hash() {
        String a = TokenHasher.sha256("hello");
        String b = TokenHasher.sha256("hello");

        assertThat(a).isEqualTo(b);
        assertThat(a).hasSize(64); // SHA-256 hex
    }

    @Test
    void 다른_입력은_다른_hash() {
        assertThat(TokenHasher.sha256("a")).isNotEqualTo(TokenHasher.sha256("b"));
    }

    @Test
    void 빈_입력은_거부() {
        assertThatThrownBy(() -> TokenHasher.sha256(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> TokenHasher.sha256(""))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
