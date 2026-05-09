package com.example.auth.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;

class JwkSourceProviderTest {

    private static RSAKey gen(String kid) throws Exception {
        return new RSAKeyGenerator(2048).keyID(kid).generate();
    }

    @Test
    void 회전_시_current_와_previous_가_둘_다_jwkSet_에_노출() throws Exception {
        JWK k1 = gen("k1");
        JWK k2 = gen("k2");
        var provider = new JwkSourceProvider(k1);

        provider.rotate(k2);

        assertThat(provider.current().getKeyID()).isEqualTo("k2");
        var ids = provider.jwkSet().getKeys().stream().map(JWK::getKeyID).toList();
        assertThat(ids).containsExactly("k2", "k1");
    }

    @Test
    void 두_번_회전하면_가장_오래된_키는_폐기된다() throws Exception {
        JWK k1 = gen("k1");
        JWK k2 = gen("k2");
        JWK k3 = gen("k3");
        var provider = new JwkSourceProvider(k1);

        provider.rotate(k2);
        provider.rotate(k3);

        var ids = provider.jwkSet().getKeys().stream().map(JWK::getKeyID).toList();
        // 직전 (k2) + 현재 (k3) 만 남음 — k1 폐기
        assertThat(ids).containsExactly("k3", "k2");
    }

    @Test
    void 사고_대응_시_previous_까지_폐기() throws Exception {
        JWK k1 = gen("k1");
        JWK k2 = gen("k2");
        var provider = new JwkSourceProvider(k1);
        provider.rotate(k2);

        provider.rotateAndDropPrevious(gen("k3"));

        var ids = provider.jwkSet().getKeys().stream().map(JWK::getKeyID).toList();
        assertThat(ids).containsExactly("k3");
    }
}
