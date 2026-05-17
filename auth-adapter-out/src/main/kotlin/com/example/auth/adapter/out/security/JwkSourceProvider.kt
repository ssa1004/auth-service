package com.example.auth.adapter.out.security

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import java.util.concurrent.atomic.AtomicReference

/**
 * JWK rotation 의 단일 소스. bootstrap 의 스케줄러가 24h 마다 새 키를 만들고 이 객체에
 * 주입합니다. issuer / verifier (Spring Authorization Server 의 JWKSource) 는 모두
 * 여기서 현재 + 직전 키를 함께 받습니다 — grace period 동안 두 키 모두 유효.
 *
 * 스레드 안전: AtomicReference. 회전 중 잠시 둘 다 원자적으로 교체.
 */
open class JwkSourceProvider {

    /** index 0 = current, index 1 = previous (있다면). */
    private val keys: AtomicReference<List<JWK>>

    constructor(initialCurrent: JWK) {
        this.keys = AtomicReference(listOf(initialCurrent))
    }

    /**
     * 부팅 시 외부 저장소 (KMS / file) 에서 previous 가 살아있던 경우 함께 주입하기 위한
     * 생성자. 두 키 모두 grace period 동안 검증 통과 (ADR-0003, ADR-0014).
     */
    constructor(initialCurrent: JWK, initialPrevious: JWK?) {
        this.keys = AtomicReference(
            if (initialPrevious == null) listOf(initialCurrent)
            else listOf(initialCurrent, initialPrevious),
        )
    }

    /** 호출 시점의 모든 활성 키 (current + previous) — JWKS endpoint 가 이걸 그대로 노출. */
    open fun jwkSet(): JWKSet = JWKSet(keys.get())

    /** 새 토큰 서명용 — 항상 현재 키. */
    open fun current(): JWK = keys.get()[0]

    /**
     * 새 키로 회전. 직전 current 가 previous 가 되고, 더 오래된 키는 폐기됩니다.
     */
    open fun rotate(newCurrent: JWK) {
        keys.updateAndGet { list -> listOf(newCurrent, list[0]) }
    }

    /** previous 까지 함께 폐기 (보안 사고 대응 시 수동 호출). */
    open fun rotateAndDropPrevious(newCurrent: JWK) {
        keys.set(listOf(newCurrent))
    }
}
