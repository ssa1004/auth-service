# ADR-0009: HikariCP 명시 튜닝 + leak detection

## 상태
적용

## 배경
Hikari 는 Spring Boot 가 기본 풀러로 깔아주지만, `maximum-pool-size` 만 기본 (10) 이고
`leak-detection-threshold` / `max-lifetime` 등 운영에 결정적인 값이 *기본값 그대로* 면
사고가 잠재합니다.

실제 운영에서 자주 만나는 사고:

- **풀 고갈** — slow query / connection 누수로 풀이 마르면 모든 요청이 30초 (기본
  `connection-timeout`) 를 기다리고 cascade timeout. 클라이언트 timeout 보다 *훨씬 늦게*
  fail 함.
- **stale connection** — RDS / CloudSQL 의 idle TCP timeout (보통 30분) 이 풀의
  `max-lifetime` 보다 짧으면 풀에 *이미 끊긴* 연결이 남아 첫 쿼리에서 예외.
- **누수 무자각** — `connection.close()` 빠뜨린 코드가 들어가도 풀 사이즈가 충분하면
  로컬에서는 안 보이고, 운영 부하가 올랐을 때 갑자기 풀이 마름.

## 결정
`spring.datasource.hikari.*` 를 *명시적으로* 박제 + 산정 근거를 yaml 주석에 함께 둡니다.

| 항목 | 값 | 근거 |
| --- | --- | --- |
| `maximum-pool-size` | 18 | 4 vCPU 기준 Hikari 권장 9 의 2배 (회전/audit/refresh 동시 가용) |
| `minimum-idle` | 4 | 야간 cold start 방지 |
| `connection-timeout` | 3000ms | 풀 고갈 시 fail-fast (기본 30s 는 cascade timeout 유발) |
| `max-lifetime` | 1740000ms (29분) | RDS/CloudSQL idle TCP timeout (30분) 보다 1분 짧게 |
| `idle-timeout` | 600000ms (10분) | min-idle 초과분 회수 |
| `leak-detection-threshold` | 30000ms | 30s 이상 잡힌 연결 stack trace 경고 |

`test` profile 은 leak detection 끔 (`@Transactional` rollback 이 long-held 처럼 보임).

## 결과
- 풀 고갈 시 클라이언트 timeout 보다 빨리 fail-fast → cascade 안 번짐.
- RDS 운영 환경에서 stale connection 첫 쿼리 실패 사라짐.
- 연결 누수 PR 이 머지되면 30초 만에 stack trace 가 로그에 찍혀 즉시 인지 가능.
- (단점) 풀 사이즈가 인스턴스 수와 곱해지므로 `max_connections` 한계를 넘으면 *PgBouncer*
  연결 풀러 도입이 다음 단계.

## 다시 검토할 시점
- 인스턴스 수가 4대 넘어 PostgreSQL `max_connections` 부담 → PgBouncer.
- p99 latency 가 풀 idle 패턴과 상관 → `connectionInitSql` 로 session 단위 튜닝.
- 트래픽 스파이크에 풀이 한 번씩 마름 → maximum-pool-size 재산정 (또는 풀러 분리).
