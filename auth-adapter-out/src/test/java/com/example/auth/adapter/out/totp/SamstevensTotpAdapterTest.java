package com.example.auth.adapter.out.totp;

import static org.assertj.core.api.Assertions.assertThat;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.junit.jupiter.api.Test;

class SamstevensTotpAdapterTest {

    @Test
    void 생성된_secret_은_길고_올바른_TOTP_검증을_통과() throws Exception {
        var adapter = new SamstevensTotpAdapter();
        String secret = adapter.generateSecret();
        assertThat(secret.length()).isGreaterThanOrEqualTo(16);

        // 같은 알고리즘 / 시간으로 직접 코드를 만들어 검증.
        CodeGenerator gen = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
        long bucket = new SystemTimeProvider().getTime() / 30;
        String code = gen.generate(secret, bucket);

        assertThat(adapter.verify(secret, code)).isTrue();
        assertThat(adapter.verify(secret, "000000")).isFalse();
    }

    @Test
    void otpAuthUrl_은_표준_포맷() {
        var adapter = new SamstevensTotpAdapter();
        String url = adapter.otpAuthUrl("alice@example.com", "auth-service", "JBSWY3DPEHPK3PXP");
        assertThat(url).startsWith("otpauth://totp/auth-service:");
        assertThat(url).contains("secret=JBSWY3DPEHPK3PXP");
    }
}
