package com.example.auth.adapter.out.security;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * JWK rotation 의 단일 소스. bootstrap 의 스케줄러가 24h 마다 새 키를 만들고 이 객체에
 * 주입합니다. issuer / verifier (Spring Authorization Server 의 JWKSource) 는 모두
 * 여기서 현재 + 직전 키를 함께 받습니다 — grace period 동안 두 키 모두 유효.
 *
 * <p>스레드 안전: AtomicReference. 회전 중 잠시 둘 다 원자적으로 교체.
 */
public class JwkSourceProvider {

    /** index 0 = current, index 1 = previous (있다면). */
    private final AtomicReference<List<JWK>> keys;

    public JwkSourceProvider(JWK initialCurrent) {
        this.keys = new AtomicReference<>(List.of(initialCurrent));
    }

    /** 호출 시점의 모든 활성 키 (current + previous) — JWKS endpoint 가 이걸 그대로 노출. */
    public JWKSet jwkSet() {
        return new JWKSet(keys.get());
    }

    /** 새 토큰 서명용 — 항상 현재 키. */
    public JWK current() {
        return keys.get().get(0);
    }

    /**
     * 새 키로 회전. 직전 current 가 previous 가 되고, 더 오래된 키는 폐기됩니다.
     */
    public void rotate(JWK newCurrent) {
        keys.updateAndGet(list -> List.of(newCurrent, list.get(0)));
    }

    /** previous 까지 함께 폐기 (보안 사고 대응 시 수동 호출). */
    public void rotateAndDropPrevious(JWK newCurrent) {
        keys.set(List.of(newCurrent));
    }
}
