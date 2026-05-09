package com.example.auth.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class AesMfaSecretCipherAdapterTest {

    private static String randomKey() {
        byte[] k = new byte[32];
        new SecureRandom().nextBytes(k);
        return Base64.getEncoder().encodeToString(k);
    }

    @Test
    void encrypt_decrypt_roundtrip() {
        var cipher = new AesMfaSecretCipherAdapter(randomKey());
        String secret = "JBSWY3DPEHPK3PXP";

        String encrypted = cipher.encrypt(secret);
        assertThat(encrypted).contains(".");
        assertThat(encrypted).doesNotContain(secret);

        assertThat(cipher.decrypt(encrypted)).isEqualTo(secret);
    }

    @Test
    void 같은_평문이라도_매번_다른_iv_로_다른_cipher_text() {
        var cipher = new AesMfaSecretCipherAdapter(randomKey());
        String s1 = cipher.encrypt("JBSWY3DPEHPK3PXP");
        String s2 = cipher.encrypt("JBSWY3DPEHPK3PXP");
        assertThat(s1).isNotEqualTo(s2);
    }

    @Test
    void 잘못된_키_길이는_즉시_거부() {
        String shortKey = Base64.getEncoder().encodeToString(new byte[16]);
        assertThatThrownBy(() -> new AesMfaSecretCipherAdapter(shortKey))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }
}
