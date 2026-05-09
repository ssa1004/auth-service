package com.example.auth.domain.common;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class EmailMaskerTest {

    @Test
    void 일반_이메일을_마스킹한다() {
        assertThat(EmailMasker.mask("alice@example.com")).isEqualTo("a***e@e***e.com");
    }

    @Test
    void 짧은_local_part_는_별표만_남긴다() {
        assertThat(EmailMasker.mask("a@example.com")).isEqualTo("a***@e***e.com");
    }

    @Test
    void 짧은_domain_은_별표만_남긴다() {
        assertThat(EmailMasker.mask("alice@x.io")).isEqualTo("a***e@x***.io");
    }

    @Test
    void null_빈문자열은_안전한_표시로_바꾼다() {
        assertThat(EmailMasker.mask(null)).isEqualTo("(blank)");
        assertThat(EmailMasker.mask("")).isEqualTo("(blank)");
        assertThat(EmailMasker.mask("   ")).isEqualTo("(blank)");
    }

    @Test
    void at_없는_문자열은_별표로_치환한다() {
        assertThat(EmailMasker.mask("notanemail")).isEqualTo("***");
        assertThat(EmailMasker.mask("@bad")).isEqualTo("***");
        assertThat(EmailMasker.mask("bad@")).isEqualTo("***");
    }
}
