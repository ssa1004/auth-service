package com.example.auth.bootstrap.jwk;

import com.example.auth.adapter.out.security.JwkSourceProvider;
import com.example.auth.application.port.out.KeyMaterialSource;
import com.example.auth.application.port.out.KeyMaterialSource.KeyMaterial;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.security.KeyPair;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 24시간마다 새 키를 생성하여 회전. 이전 키는 1 cycle 더 살아남아 grace period 동안
 * 두 토큰이 모두 검증 통과합니다 (ADR-0003).
 *
 * <p>운영에서는 단일 leader 만 회전을 수행해야 합니다 (k8s leader election 또는 DB
 * advisory lock). 현재 구현은 단일 인스턴스 가정.
 *
 * <p>회전 결과는 {@link KeyMaterialSource} 에 박제됩니다 (ADR-0014). KMS / 디스크 어느
 * 백엔드든 같은 인터페이스로 회전.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwkRotationScheduler {

    private final JwkSourceProvider provider;
    private final KeyMaterialSource keyMaterialSource;

    /** 매일 자정 (UTC). */
    @Scheduled(cron = "0 0 0 * * *", zone = "UTC")
    public void rotate() {
        try {
            String kid = UUID.randomUUID().toString();
            RSAKey newJwk = new RSAKeyGenerator(2048)
                    .keyID(kid)
                    .keyUse(KeyUse.SIGNATURE)
                    .generate();
            // 영구 저장소에 먼저 박제 — 실패하면 in-memory 회전도 안 함 (key 불일치 사고 방지).
            KeyPair pair = new KeyPair(newJwk.toRSAPublicKey(), newJwk.toRSAPrivateKey());
            keyMaterialSource.rotate(new KeyMaterial(kid, pair));
            // 영속 박제 성공 후 in-memory 도 회전.
            provider.rotate(newJwk);
            log.info("JWK rotated newKid={} jwkSetSize={}", newJwk.getKeyID(),
                    provider.jwkSet().size());
        } catch (Exception e) {
            // 회전 실패해도 직전 cycle 의 키는 그대로 남으므로 즉시 장애로는 이어지지 않음.
            log.error("JWK rotation failed", e);
        }
    }
}
