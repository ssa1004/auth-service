package com.example.auth.adapter.out.security;

import com.example.auth.application.port.out.KeyMaterialSource;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;

/**
 * 운영 KMS / Vault 백엔드 placeholder (ADR-0014).
 *
 * <p>본 시점에는 *interface 만* 추상화. AWS SDK / HashiCorp Vault SDK 를 본 모듈에
 * 강제 의존시키지 않기 위해 wiring 은 README 의 "운영 wiring 가이드" 단락 참조.
 *
 * <p>구현 권장:
 * <ul>
 *   <li><b>AWS KMS</b> — RSA_2048 KeyUsage=SIGN_VERIFY 비대칭 키. {@code GetPublicKey} +
 *       {@code Sign} API. 키 회전은 KMS alias 가 자동 — store(newCurrent) 는 alias 갱신.
 *       애플리케이션은 *private key 를 직접 가지지 않고* KMS API 로 서명 위임.
 *       (그러면 본 인터페이스의 KeyPair 모양은 안 맞음 — 별도 SigningKeyMaterialSource
 *       interface 도입 후속.)</li>
 *   <li><b>HashiCorp Vault</b> — transit secrets engine. {@code vault write transit/keys/auth}.
 *       Key 자체는 Vault 안에 박제, 응용은 sign API 를 호출.</li>
 *   <li><b>K8s Secret + Sealed Secrets</b> — 가장 단순. SealedSecret 으로 git 커밋,
 *       Bitnami Sealed Secrets controller 가 cluster 안에서 unseal.</li>
 * </ul>
 *
 * <p>현 시점에는 사용 시 명확한 예외 — 운영 wiring 누락을 부팅 시점에 즉시 인지하기 위함.
 */
@Slf4j
public class KmsKeyMaterialSource implements KeyMaterialSource {

    @Override
    public KeyMaterial loadOrInitCurrent() {
        throw new UnsupportedOperationException(
                "KmsKeyMaterialSource — 운영 KMS / Vault wiring 미구현. "
                        + "README 의 '운영 wiring 가이드' 단락 참조 (ADR-0014).");
    }

    @Override
    public Optional<KeyMaterial> loadPrevious() {
        return Optional.empty();
    }

    @Override
    public void rotate(KeyMaterial newCurrent) {
        throw new UnsupportedOperationException(
                "KmsKeyMaterialSource.rotate — 운영 KMS / Vault wiring 미구현.");
    }
}
