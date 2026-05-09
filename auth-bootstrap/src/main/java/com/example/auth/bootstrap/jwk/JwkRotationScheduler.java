package com.example.auth.bootstrap.jwk;

import com.example.auth.adapter.out.security.JwkSourceProvider;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
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
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwkRotationScheduler {

    private final JwkSourceProvider provider;

    /** 매일 자정 (UTC). */
    @Scheduled(cron = "0 0 0 * * *", zone = "UTC")
    public void rotate() {
        try {
            RSAKey newKey = new RSAKeyGenerator(2048)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            provider.rotate(newKey);
            log.info("JWK rotated newKid={} jwkSetSize={}", newKey.getKeyID(),
                    provider.jwkSet().size());
        } catch (Exception e) {
            // 회전 실패해도 직전 cycle 의 키는 그대로 남으므로 즉시 장애로는 이어지지 않음.
            log.error("JWK rotation failed", e);
        }
    }
}
