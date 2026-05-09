package com.example.auth.application.port.out;

import java.security.KeyPair;
import java.util.Optional;

/**
 * JWK 의 영구 저장소 추상화 (ADR-0014). 의도적으로 JDK 표준 {@link KeyPair} 만 노출 —
 * Nimbus JOSE 같은 라이브러리에 비의존.
 *
 * <p>구현체는 두 가지:
 * <ul>
 *   <li>{@code LocalFileKeyMaterialSource} — dev/local 용 디스크 파일 (gitignored).</li>
 *   <li>{@code KmsKeyMaterialSource} — 운영용 AWS KMS / HashiCorp Vault. 본 시점에는
 *       interface 만 추상화하고 실제 KMS SDK 도입은 README "운영 wiring 가이드" 단계에서.</li>
 * </ul>
 */
public interface KeyMaterialSource {

    /**
     * 부팅 시 current 키를 로드. 저장된 키가 없으면 새로 생성 후 store 하여 반환.
     */
    KeyMaterial loadOrInitCurrent() throws Exception;

    /** 직전 키 (rotation 후 grace period 동안 유효). 없으면 empty. */
    Optional<KeyMaterial> loadPrevious() throws Exception;

    /**
     * 회전 시 호출. 직전 current → previous 슬롯, 새 키가 current 슬롯.
     *
     * @throws Exception 저장 실패 — JwkRotationScheduler 가 catch 하여 다음 cycle 재시도.
     *                   실패해도 in-memory 의 직전 키는 그대로라 즉시 장애로 이어지지 않음.
     */
    void rotate(KeyMaterial newCurrent) throws Exception;

    /** 한 키의 KeyPair + kid 묶음. */
    record KeyMaterial(String kid, KeyPair keyPair) {
    }
}
