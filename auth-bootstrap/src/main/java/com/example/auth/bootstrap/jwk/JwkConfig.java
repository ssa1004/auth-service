package com.example.auth.bootstrap.jwk;

import com.example.auth.adapter.out.security.JwkSourceProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * JWK 의 단일 소스 빈 등록.
 *
 * <p>최초 부팅 시 RSA 2048 키 한 쌍을 생성합니다 (운영에서는 KMS / Vault 에서 주입).
 * 이후 {@link JwkRotationScheduler} 가 24시간마다 회전합니다 (ADR-0003).
 *
 * <p>Spring Authorization Server 의 {@link JWKSource} 는 매 요청마다 최신 JWKSet 을
 * 봅니다 — provider.jwkSet() 이 항상 current + previous 둘 다 노출하여 회전 직후의 토큰도
 * grace period 동안 검증 통과합니다.
 */
@Configuration
public class JwkConfig {

    @Bean
    public JwkSourceProvider jwkSourceProvider() throws Exception {
        RSAKey initial = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        return new JwkSourceProvider(initial);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(JwkSourceProvider provider) {
        // jwkSelector 가 호출될 때마다 provider 의 최신 키들을 노출.
        return (jwkSelector, securityContext) -> {
            JWKSet set = provider.jwkSet();
            return jwkSelector.select(set);
        };
    }
}
