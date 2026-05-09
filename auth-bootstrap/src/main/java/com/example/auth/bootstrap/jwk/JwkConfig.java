package com.example.auth.bootstrap.jwk;

import com.example.auth.adapter.out.security.JwkSourceProvider;
import com.example.auth.adapter.out.security.KmsKeyMaterialSource;
import com.example.auth.adapter.out.security.LocalFileKeyMaterialSource;
import com.example.auth.application.port.out.KeyMaterialSource;
import com.example.auth.application.port.out.KeyMaterialSource.KeyMaterial;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * JWK 의 단일 소스 빈 등록 (ADR-0003 + ADR-0014).
 *
 * <p>{@link KeyMaterialSource} 가 영구 저장소 (local file / KMS) 와 추상화. 여기서는
 * 부팅 시 current + previous 를 로드하여 {@link JwkSourceProvider} 에 주입.
 *
 * <p>{@link JwkRotationScheduler} 가 24시간마다 회전 — 회전 시 {@link KeyMaterialSource}
 * 에 박제 (KMS 또는 local-jwk.json).
 */
@Configuration
public class JwkConfig {

    /**
     * 기본 (dev/local) — local-jwk.json 디스크 파일.
     */
    @Bean
    @ConditionalOnMissingBean(KeyMaterialSource.class)
    @ConditionalOnProperty(prefix = "auth.jwk", name = "source", havingValue = "local",
            matchIfMissing = true)
    public KeyMaterialSource localFileKeyMaterialSource(
            @Value("${auth.jwk.local-path:./local-jwk.json}") String path) {
        return new LocalFileKeyMaterialSource(Path.of(path));
    }

    /**
     * 운영 — auth.jwk.source=kms. 본 시점에는 placeholder — 사용 시 부팅이 fail-fast 함으로써
     * 운영 wiring 누락을 즉시 인지. (ADR-0014 의 README 단락 참조)
     */
    @Bean
    @ConditionalOnMissingBean(KeyMaterialSource.class)
    @ConditionalOnProperty(prefix = "auth.jwk", name = "source", havingValue = "kms")
    public KeyMaterialSource kmsKeyMaterialSource() {
        return new KmsKeyMaterialSource();
    }

    @Bean
    public JwkSourceProvider jwkSourceProvider(KeyMaterialSource keyMaterialSource) throws Exception {
        KeyMaterial current = keyMaterialSource.loadOrInitCurrent();
        JWK currentJwk = toJwk(current);
        JWK previousJwk = keyMaterialSource.loadPrevious()
                .map(JwkConfig::toJwk)
                .orElse(null);
        return new JwkSourceProvider(currentJwk, previousJwk);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(JwkSourceProvider provider) {
        return (jwkSelector, securityContext) -> {
            JWKSet set = provider.jwkSet();
            return jwkSelector.select(set);
        };
    }

    private static JWK toJwk(KeyMaterial m) {
        return new RSAKey.Builder((RSAPublicKey) m.keyPair().getPublic())
                .privateKey((RSAPrivateKey) m.keyPair().getPrivate())
                .keyID(m.kid())
                .keyUse(KeyUse.SIGNATURE)
                .build();
    }
}
