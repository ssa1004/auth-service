package com.example.auth.bootstrap.jwk

import com.example.auth.adapter.out.security.JwkSourceProvider
import com.example.auth.adapter.out.security.KmsKeyMaterialSource
import com.example.auth.adapter.out.security.LocalFileKeyMaterialSource
import com.example.auth.application.port.out.KeyMaterialSource
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import java.nio.file.Path
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * JWK 의 단일 소스 빈 등록 (ADR-0003 + ADR-0014).
 *
 * [KeyMaterialSource] 가 영구 저장소 (local file / KMS) 를 추상화합니다. 여기서는
 * 부팅 시 current + previous 를 로드하여 [JwkSourceProvider] 에 주입합니다.
 *
 * [JwkRotationScheduler] 가 24시간마다 회전. 회전 시 [KeyMaterialSource] 에
 * 영속화합니다 (KMS 또는 local-jwk.json).
 */
@Configuration
open class JwkConfig {

    /**
     * 기본 (dev/local) — local-jwk.json 디스크 파일.
     */
    @Bean
    @ConditionalOnMissingBean(KeyMaterialSource::class)
    @ConditionalOnProperty(
        prefix = "auth.jwk",
        name = ["source"],
        havingValue = "local",
        matchIfMissing = true,
    )
    open fun localFileKeyMaterialSource(
        @Value("\${auth.jwk.local-path:./local-jwk.json}") path: String,
    ): KeyMaterialSource = LocalFileKeyMaterialSource(Path.of(path))

    /**
     * 운영 — auth.jwk.source=kms. 본 시점에는 placeholder — 사용 시 부팅이 fail-fast 함으로써
     * 운영 wiring 누락을 즉시 인지. (ADR-0014 의 README 단락 참조)
     */
    @Bean
    @ConditionalOnMissingBean(KeyMaterialSource::class)
    @ConditionalOnProperty(prefix = "auth.jwk", name = ["source"], havingValue = "kms")
    open fun kmsKeyMaterialSource(): KeyMaterialSource = KmsKeyMaterialSource()

    @Bean
    open fun jwkSourceProvider(keyMaterialSource: KeyMaterialSource): JwkSourceProvider {
        val current = keyMaterialSource.loadOrInitCurrent()
        val currentJwk = toJwk(current)
        val previousJwk = keyMaterialSource.loadPrevious()
            .map { toJwk(it) }
            .orElse(null)
        return JwkSourceProvider(currentJwk, previousJwk)
    }

    @Bean
    open fun jwkSource(provider: JwkSourceProvider): JWKSource<SecurityContext> =
        JWKSource { jwkSelector, _ ->
            val set: JWKSet = provider.jwkSet()
            jwkSelector.select(set)
        }

    companion object {
        private fun toJwk(m: KeyMaterial): JWK =
            RSAKey.Builder(m.keyPair.public as RSAPublicKey)
                .privateKey(m.keyPair.private as RSAPrivateKey)
                .keyID(m.kid)
                .keyUse(KeyUse.SIGNATURE)
                .build()
    }
}

private typealias KeyMaterial = KeyMaterialSource.KeyMaterial
