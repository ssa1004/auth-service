# ADR-0010: K8s 3종 probe 분리 + ApplicationReadinessCoordinator

## 상태
적용

## 배경
Kubernetes 에는 컨테이너 상태를 점검하는 probe 가 3종 있습니다.

- `startupProbe` — 부팅 중. 통과 전까지 readiness / liveness 잠김.
- `readinessProbe` — 트래픽을 받을 수 있는가. 실패 시 Service endpoint 에서 제거.
- `livenessProbe` — 프로세스가 살아있는가. 실패 시 컨테이너 재시작.

자주 보는 사고 시나리오:

- **부팅이 느린 인스턴스가 죽음** — startup probe 없이 liveness probe 만 두면 Spring Boot
  + Flyway + JWK 초기 키 생성까지 30초 걸리는 부팅을 K8s 가 liveness 실패로 오인하고
  컨테이너를 영원히 재시작합니다.
- **DB 일시 장애로 살아있는 pod 가 죽음** — liveness probe 가 외부 의존 (DB / Redis) 까지
  포함하면, DB 가 잠깐 흔들렸을 때 살아있는 pod 들을 동시에 재시작 → 장애가 더 커집니다.
- **트래픽 받는데 의존이 down** — readiness probe 가 외부 의존을 보지 않으면, DB down 인
  pod 가 5xx 를 계속 뱉는데도 K8s 는 트래픽을 계속 보냅니다.

## 결정

### probe 3종 분리
- `startupProbe` — 5s * 30 = 150s 부팅 허용. `/actuator/health/readiness` 호출.
- `readinessProbe` — 10s 주기. `/actuator/health/readiness`. 그룹에 `readinessState + db + redis`.
- `livenessProbe` — 20s 주기. `/actuator/health/liveness`. 그룹에 `livenessState` *만*
  (외부 의존 미포함).

### `ApplicationReadinessCoordinator`
- `@EventListener(ApplicationReadyEvent)` 에서 JWK 초기 키 미생성 시 `IllegalStateException`
  발생 → 컨테이너 종료 코드 1 → K8s 재시작 (KMS 도입 후 KMS 응답 실패 케이스 대비).
- `@Scheduled(fixedDelay=5s)` 가 `HealthContributorRegistry` 에서 `db`, `redis` 의 health 를
  깨워 연속 3회 실패면 `ReadinessState.REFUSING_TRAFFIC` 으로 전환.
- 의존이 회복되면 다시 `ACCEPTING_TRAFFIC` 으로 자동 복귀.
- 연속 N회 (3) 임계값 — 외부 의존이 잠깐 흔들렸을 때마다 readiness 를 토글하면 노이즈가
  너무 많아집니다.

### 그룹 구성 (`management.endpoint.health.group`)
```yaml
readiness:
  include: readinessState, db, redis
liveness:
  include: livenessState
```

## 결과
- 부팅이 느려도 startup probe 가 잡고 있어 liveness 가 잘못 발동하지 않습니다.
- DB 일시 장애로 살아있는 pod 가 줄줄이 재시작되는 사고가 발생하지 않습니다.
- DB / Redis 가 꺼지면 5초 안에 readiness=DOWN → K8s 가 트래픽 차단 → 5xx 가 외부로
  새지 않습니다.

## 다시 검토할 시점
- p99 가 readiness 토글 직후 잠깐 튐 → graceful drain 시간 조정.
- 외부 의존이 더 늘면 (Kafka / 외부 IdP) coordinator 에 contributor 추가.
- KMS 도입 후 JWK 키 미생성 케이스가 빈번해지면 startup probe failure threshold 조정.

## 용어 풀이 (쉽게)

- **probe (상태 점검)** — 쿠버네티스가 컨테이너 안부를 주기적으로 묻는 검사. startup(부팅 다 됐어?), readiness(손님 받아도 돼?), liveness(살아는 있어?) 세 종류로 역할을 나눈다.
- **liveness에 외부 의존을 안 넣는 이유** — liveness가 실패하면 컨테이너를 재시작하는데, 여기에 DB·Redis 상태를 넣으면 DB가 잠깐 흔들렸을 때 멀쩡한 pod들까지 줄줄이 재시작돼 장애가 더 커진다. 그래서 liveness는 '나 자신만' 본다.
- **ReadinessState (트래픽 수용 상태)** — 'ACCEPTING_TRAFFIC(받음) ↔ REFUSING_TRAFFIC(거부)'를 오가는 깃발. 의존이 죽으면 거부로 바꿔 쿠버네티스가 이 pod로 손님을 안 보내게 하고, 회복되면 자동으로 다시 받음으로 돌린다.
