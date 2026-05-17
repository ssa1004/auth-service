package com.example.auth.bootstrap.jwk

import com.example.auth.adapter.out.security.JwkSourceProvider
import com.example.auth.application.port.out.KeyMaterialSource
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import java.security.KeyPair
import java.util.UUID
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component

/**
 * 24시간마다 새 키를 생성하여 회전. 이전 키는 1 cycle 더 살아남아 grace period 동안
 * 두 토큰이 모두 검증을 통과합니다 (ADR-0003).
 *
 * 운영에서는 단일 leader 만 회전을 수행해야 합니다 (k8s leader election 또는 DB
 * advisory lock). 현재 구현은 단일 인스턴스 가정.
 *
 * 회전 결과는 [KeyMaterialSource] 에 영속화됩니다 (ADR-0014). KMS / 디스크 어느
 * 백엔드든 같은 인터페이스로 회전합니다.
 */
@Component
open class JwkRotationScheduler(
    private val provider: JwkSourceProvider,
    private val keyMaterialSource: KeyMaterialSource,
) {

    /** 매일 자정 (UTC). */
    @Scheduled(cron = "0 0 0 * * *", zone = "UTC")
    open fun rotate() {
        try {
            val kid = UUID.randomUUID().toString()
            val newJwk = RSAKeyGenerator(2048)
                .keyID(kid)
                .keyUse(KeyUse.SIGNATURE)
                .generate()
            // 영구 저장소에 먼저 저장. 실패하면 in-memory 회전도 하지 않음 (key 불일치 사고 방지).
            val pair = KeyPair(newJwk.toRSAPublicKey(), newJwk.toRSAPrivateKey())
            keyMaterialSource.rotate(KeyMaterialSource.KeyMaterial(kid, pair))
            // 영속 저장 성공 후 in-memory 도 회전.
            provider.rotate(newJwk)
            log.info("JWK rotated newKid={} jwkSetSize={}", newJwk.keyID, provider.jwkSet().size())
        } catch (e: Exception) {
            // 회전 실패해도 직전 cycle 의 키는 그대로 남으므로 즉시 장애로는 이어지지 않음.
            log.error("JWK rotation failed", e)
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(JwkRotationScheduler::class.java)
    }
}
