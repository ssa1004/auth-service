# ADR-0014: JWK 외부 KMS 추상화 (KeyMaterialSource)

## 상태
적용 (interface + LocalFile 구현, KMS 구현은 placeholder)

## 배경
기존 `JwkConfig` 는 부팅 시점에 RSA 2048 을 *in-memory 로* 생성. 단점:

- pod 가 죽으면 키도 같이 죽음 → 모든 access token 이 invalid (consumer 의 JWKS cache hit 도
  깨짐).
- pod 여러 대일 때 각자 다른 키 → 같은 사용자의 토큰이 어떤 pod 에 가느냐에 따라 검증 실패.
- 운영의 표준 패턴 — KMS / Vault — 와 어긋남.

운영 환경의 표준:

- **AWS KMS** — `RSA_2048` Key 비대칭, `Sign` API. 응용은 *private key 자체를 안 가지고*
  KMS 로 서명 위임.
- **HashiCorp Vault transit secrets engine** — 비슷한 패턴. Vault 가 키 보관 + sign API.
- **K8s Secret + Sealed Secrets** — 가장 단순. SealedSecret 으로 git 커밋, controller 가
  unseal 후 Secret 으로.

본 ADR 은 위 셋 어느 것이든 끼울 수 있게 *interface 만* 추상화. 실제 KMS / Vault SDK 는
라이브러리 의존성을 본 모듈에 묶지 않기 위해 별도 wiring (README) 으로.

## 결정

### `KeyMaterialSource` 포트
```java
public interface KeyMaterialSource {
    KeyMaterial loadOrInitCurrent() throws Exception;
    Optional<KeyMaterial> loadPrevious() throws Exception;
    void rotate(KeyMaterial newCurrent) throws Exception;

    record KeyMaterial(String kid, KeyPair keyPair) {}
}
```

JDK 표준 `java.security.KeyPair` 만 노출 — Nimbus JOSE / 다른 라이브러리 비의존.

### 구현 두 가지
- `LocalFileKeyMaterialSource` (dev/local) — `local-jwk.json` 디스크 파일. 부팅 시 파일이
  없으면 키 생성, 회전 시 previous 슬롯에 직전 키 박제.
- `KmsKeyMaterialSource` (prod placeholder) — `loadOrInitCurrent()` / `rotate()` 호출 시
  `UnsupportedOperationException` 으로 fail-fast — 운영 wiring 누락을 부팅 시점에 즉시 인지.

### 환경별 선택
```yaml
auth:
  jwk:
    source: ${AUTH_JWK_SOURCE:local}      # 'local' | 'kms'
    local-path: ${AUTH_JWK_LOCAL_PATH:./local-jwk.json}
```

`@ConditionalOnProperty` 로 `JwkConfig` 가 `KeyMaterialSource` 빈을 한 종류만 등록.

### `JwkRotationScheduler` 변경
회전 직전에 `keyMaterialSource.rotate(...)` 를 *먼저* 호출 — 영속 박제가 실패하면 in-memory
회전도 안 함. 실패해도 직전 키는 그대로 유효 → 즉시 장애 안 남.

## 결과
- dev 에서는 파일 한 개로 키 영속 → pod 재시작 후에도 같은 키.
- 운영 wiring 만 끼우면 본 application 코드는 그대로.
- 도메인 / 응용 코드는 KMS 라이브러리에 비의존 — 이식성.

## 다시 검토할 시점
- AWS KMS Sign API 를 채택할 때 → private key 자체를 응용이 가지지 않는 모델로 전환 → 별도
  `SigningKeyMaterialSource` 인터페이스 분리 (sign(payload) 호출 위임).
- 다중 pod 에서 회전 동시성 → DB advisory lock 또는 K8s leader election.
- 직전 키만 살리는 게 아니라 N 세대 살리고 싶을 때 → KeyMaterialSource 가 list 반환.
