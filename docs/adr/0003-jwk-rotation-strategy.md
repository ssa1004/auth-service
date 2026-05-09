# ADR-0003: JWK rotation — 24h cycle + grace period

## 상태
적용

## 배경
JWT 서명 키 (private key) 를 평생 같은 값으로 두면 두 가지 위험이 있습니다.

1. 키가 한 번 새 나가면 모든 발행 토큰이 위조 가능 — 사고의 영향 범위가 시간 무제한으로
   확장됩니다.
2. 알고리즘 / 키 길이 deprecate 시 점진 교체 경로가 없어 빅뱅 회전이 강제됩니다.

회전을 자주 하면 안전하지만, 회전 직후에 발행된 access token 이 verifier 측 캐시 만료
전까지 검증을 통과해야 합니다. JWKS endpoint 가 현재 키 + 직전 키를 둘 다 노출하지 않으면
회전 즉시 401 폭주가 일어납니다.

## 결정
24시간마다 자동 회전. 직전 키는 1 cycle (=24시간) 동안 verify-only 로 유지합니다.

구현:
- `JwkSourceProvider` — `AtomicReference<List<JWK>>`. index 0 = current (sign + verify),
  index 1 = previous (verify only).
- `JwkRotationScheduler` — `@Scheduled(cron="0 0 0 * * *", zone="UTC")`. 새 키 생성 후 atomic
  교체. 더 오래된 키는 폐기.
- `JWKSource<SecurityContext>` 는 매 호출마다 provider.jwkSet() 을 그대로 노출하므로
  Spring Authorization Server 의 `/oauth2/jwks` endpoint 에 즉시 반영됩니다.

사고 대응 경로: `JwkSourceProvider.rotateAndDropPrevious(newKey)` 호출 한 번으로 직전 키
까지 폐기. 운영 endpoint 또는 admin CLI 를 통해 수동 발동합니다.

## 결과
- access token TTL 15분 + grace period 24시간이라 회전 시점에 발행된 토큰의 verify 실패
  확률은 사실상 0.
- JWKS endpoint 의 응답이 1KB 이하 — verifier 캐시에 부담 없음.
- (단점) 단일 인스턴스 가정. 다중 인스턴스 운영 시 leader election (k8s lease 또는 DB
  advisory lock) 으로 회전 주체를 1개로 강제하는 후속 작업이 필요합니다.
- (단점) 키 자료가 메모리에만 존재합니다. 인스턴스 재시작 시 회전 cycle 이 다시
  시작됩니다. 운영에서는 KMS / Vault 에서 외부 주입 + 안정 키 ID 유지 (ADR-0014).

## 다시 검토할 시점
- 키 유출 / 임직원 이탈 / 키 자료를 가진 서버에 침해가 의심되는 사고 시 즉시 수동 회전.
- 다중 인스턴스 / k8s 운영 시 leader election 도입.
