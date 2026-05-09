# ADR-0009: HikariCP 명시 튜닝 + leak detection

## 상태
적용

## 배경
Hikari 는 Spring Boot 가 기본 풀러로 깔아줍니다. 하지만 `maximum-pool-size` 만 기본
(10) 이고 `leak-detection-threshold` / `max-lifetime` 같은 운영에 결정적인 값을 기본값
그대로 두면 사고가 누적됩니다.

운영에서 자주 만나는 사고 시나리오:

- **풀 고갈** — slow query 나 connection 누수로 풀이 마르면 모든 요청이 30초 (기본
  `connection-timeout`) 를 기다리다 줄줄이 timeout 됩니다. 클라이언트 timeout 보다 훨씬
  늦게 fail 하므로 사용자 입장에서는 "응답이 한참 멈춰 있다가 5xx" 패턴이 됩니다.
- **stale connection** — RDS / CloudSQL 의 idle TCP timeout (보통 30분) 이 풀의
  `max-lifetime` 보다 짧으면 풀에 이미 끊긴 연결이 남아 첫 쿼리에서 예외가 발생합니다.
- **누수 무자각** — `connection.close()` 를 빠뜨린 코드가 들어가도 풀 사이즈가 충분하면
  로컬에서는 보이지 않고, 운영 부하가 올랐을 때 갑자기 풀이 마릅니다.

## 결정
`spring.datasource.hikari.*` 의 모든 항목을 명시적으로 지정하고 산정 근거를 yaml 주석에
함께 둡니다.

| 항목 | 값 | 근거 |
| --- | --- | --- |
| `maximum-pool-size` | 18 | 4 vCPU 기준 Hikari 권장 9 의 2배 (회전/audit/refresh 동시 가용) |
| `minimum-idle` | 4 | 야간 cold start 방지 |
| `connection-timeout` | 3000ms | 풀 고갈 시 fail-fast (기본 30s 는 줄줄이 timeout 유발) |
| `max-lifetime` | 1740000ms (29분) | RDS/CloudSQL idle TCP timeout (30분) 보다 1분 짧게 |
| `idle-timeout` | 600000ms (10분) | min-idle 초과분 회수 |
| `leak-detection-threshold` | 30000ms | 30s 이상 잡힌 연결 stack trace 경고 |

`test` profile 에서는 leak detection 을 끕니다 (`@Transactional` rollback 이 long-held
처럼 보이기 때문).

## 결과
- 풀 고갈 시 클라이언트 timeout 보다 빨리 fail-fast 하므로 다른 서비스로 장애가 번지지
  않습니다.
- RDS 운영 환경에서 stale connection 의 첫 쿼리 실패가 사라집니다.
- 연결 누수 PR 이 머지되면 30초 만에 stack trace 가 로그에 찍혀 즉시 인지 가능합니다.
- (단점) 풀 사이즈가 인스턴스 수와 곱해지므로 `max_connections` 한계를 넘으면 PgBouncer
  같은 연결 풀러 도입이 다음 단계가 됩니다.

## 다시 검토할 시점
- 인스턴스 수가 4대 넘어 PostgreSQL `max_connections` 부담 → PgBouncer.
- p99 latency 가 풀 idle 패턴과 상관 → `connectionInitSql` 로 session 단위 튜닝.
- 트래픽 스파이크에 풀이 한 번씩 마름 → maximum-pool-size 재산정 (또는 풀러 분리).
