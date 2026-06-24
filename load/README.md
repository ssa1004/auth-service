# Load Tests — k6

[k6](https://k6.io/) (JavaScript 시나리오) 부하 / invariant 검증 스크립트 모음. auth-service 의
OAuth2 표준 endpoint + first-party `/api/v1/auth/*` 흐름을 대상으로 합니다.

## 시나리오

| 파일 | endpoint | 패턴 | 측정 의도 |
|---|---|---|---|
| `scenarios/token-issue.js` | `POST /oauth2/token` (client_credentials) | constant 500 req/s, 1m | JWT 발급 throughput. BCrypt secret verify + RS256 sign 지배 |
| `scenarios/token-introspect.js` | `POST /oauth2/introspect` (RFC 7662) | constant 1000 req/s, 1m | Read-heavy. Redis introspect 캐시 적중률 |
| `scenarios/jwks-fetch.js` | `GET /oauth2/jwks` | constant 2000 req/s, 30s | 정적 응답 + JWK Set 캐싱 효과 |
| `scenarios/login-refresh.js` | `POST /auth/login` → `POST /auth/refresh` | ramping 0 → 100 VU, 3m | end-user 흐름. login + refresh rotation latency |
| `scenarios/refresh-reuse-detection.js` | `POST /auth/refresh` (의도적 reuse) | shared-iterations, 1 VU | ADR-0004 invariant — 두 번째 사용은 401 + family revoke(= 이미 회전돼 버려진 옛 출입증이 다시 들어오면 탈취로 의심해 그 사용자의 모든 세션 출입증을 한꺼번에 무효화 — 카드 복제 의심 시 그 사람 카드 전부 정지) |

## 측정 항목 (OAuth2 특유)

일반적인 RPS / latency 외에 OAuth2 / refresh rotation 모델 특유의 항목을 같이 봅니다.

- **`token_issue` p95** — `/oauth2/token` 의 p95. BCrypt cost 12 + RS256 sign 이 지배.
  100ms 초과 시 CPU bound / JCE provider 튜닝 여지 의심 ([ADR-0002](../docs/adr/0002-rs256-vs-eddsa.md)).
- **`introspect_active_rate`** (custom Rate) — fixture token 의 `active=true` 비율. 캐시 무효 /
  Redis 장애 발생 시 false 비율이 증가합니다. 1.0 미달 = 캐시 / IdP 측 문제 신호.
- **`introspect` p95** — 캐시 적중 시 p95 < 20ms. 초과 시 JWT 재서명 검증 / DB 조회 fallthrough.
- **`jwks` p95** — 정적 자료 + 캐싱이라 p95 < 10ms. 초과 시 매 호출 JWKSet 직렬화 가능성.
- **`refresh_rotation_collision`** (개념) — 같은 refresh 가 동시에 두 번 들어오는 race.
  본 시나리오에서는 직접 측정하지 않지만 `refresh-reuse-detection.js` 가 4단계 invariant
  (`reuse_login`, `reuse_rotate_ok`, `reuse_second_use_401`, `reuse_family_revoked`) 의 100%
  통과로 _구조적_ 정합성을 보장합니다 ([ADR-0004](../docs/adr/0004-refresh-token-rotation-and-reuse-detection.md),
  [ADR-0015](../docs/adr/0015-refresh-reuse-grace-window.md)).

## thresholds

각 시나리오는 자체 `thresholds` 를 가지고 있으며, 위반 시 k6 종료 코드가 nonzero 가 되어
CI 의 nightly job 이 fail 처리합니다.

| 시나리오 | 임계 | 근거 |
|---|---|---|
| token-issue | p95 < 100ms, err < 1% | BCrypt + RS256 sign 평상시 한계 |
| token-introspect | p95 < 20ms, err < 1%, `introspect_active_rate` > 0.99 | Redis 캐시 적중 가정 |
| jwks-fetch | p95 < 10ms, err < 0.1% | 정적 + 캐싱 |
| login-refresh | login / refresh 각 p95 < 150ms, err < 1% | end-user 흐름 |
| refresh-reuse-detection | 4단계 invariant 100% 통과 (rate == 1.0) | 부하가 아닌 보안 검증 |

## 실행

```bash
# k6 설치 (Mac)
brew install k6

# 단일 시나리오 실행
k6 run load/k6/scenarios/token-issue.js
k6 run load/k6/scenarios/token-introspect.js
k6 run load/k6/scenarios/jwks-fetch.js
k6 run load/k6/scenarios/login-refresh.js
k6 run load/k6/scenarios/refresh-reuse-detection.js

# 일괄 실행
./scripts/run-load.sh
```

환경 변수로 대상 / 인증을 override 합니다 (자세한 항목은 `lib/config.js`):

```bash
BASE_URL=http://localhost:8080 \
CLIENT_ID=internal-service \
CLIENT_SECRET=internal-service-secret-change-me \
TENANT_SLUG=acme USER_EMAIL=alice@example.com USER_PASSWORD=longenoughpw1234 \
k6 run load/k6/scenarios/login-refresh.js
```

### 사전 준비

- `token-issue` / `token-introspect` / `jwks-fetch` — auth-service 가 떠 있기만 하면 됩니다
  (`internal-service` client 는 `AuthorizationServerClientsConfig` 의 로컬 시드).
- `login-refresh` / `refresh-reuse-detection` — `USER_EMAIL` / `USER_PASSWORD` 의 사용자가
  미리 register 되어 있어야 합니다.

  ```bash
  curl -X POST localhost:8080/api/v1/auth/register \
    -H 'Content-Type: application/json' \
    -d '{"tenantSlug":"acme","email":"alice@example.com","password":"longenoughpw1234"}'
  ```

## docker-compose 통합 (선택)

`infrastructure/docker/docker-compose.integration.yml` 의 `k6` 서비스로 위 시나리오를
컨테이너 안에서 실행할 수 있습니다 — 외부 의존 없이 docker network 안에서 닫혀 있습니다.

```bash
docker compose -f infrastructure/docker/docker-compose.integration.yml \
  --profile load run --rm k6 run /k6/scenarios/token-issue.js
```

## 운영 secret 주의

- `CLIENT_SECRET` / `USER_PASSWORD` 는 절대 commit 하지 않습니다. 기본값은 로컬 시드 한정.
- k6 로그 / artifact 에 평문 token 이 들어가지 않도록 `--summary-export` 만 보관하고
  본문은 따로 떨어뜨립니다 ([CONTRIBUTING.md](../CONTRIBUTING.md) 의 보안 규칙 참고).

## Prometheus remote-write 연동 (commerce-ops 통합 대시보드)

각 시나리오 결과를 `commerce-ops` 의 Prometheus 로 흘려서 한 Grafana 대시보드에서
client load + auth-service actuator 를 같이 보고 싶을 때:

```bash
# commerce-ops 의 Prom 은 이미 remote-write receiver 가 켜져 있다
docker compose -f /path/to/commerce-ops/infra/docker-compose.yml up -d prometheus grafana

export K6_PROMETHEUS_RW_SERVER_URL=http://localhost:9090/api/v1/write
./scripts/run-load.sh
```

`run-load.sh` 가 각 시나리오에 `service=auth-service` / `scenario=<name>` tag 를 자동
부여한다. Grafana → **Portfolio Load (k6 + actuator)** 대시보드 (uid `portfolio-load`)
에서 service 변수를 `auth-service` 로 선택하면 token_issue / introspect / login-refresh /
refresh-reuse-detection 의 throughput / p95 / p99 / error rate 와 actuator 의 process
CPU / JVM heap / HikariCP 가 같은 시간축에 plot 된다. 필요 k6 버전 **0.42+**
(experimental-prometheus-rw output).

## 후속 작업

- [ ] CI 의 nightly job 에 `scripts/run-load.sh` 통합
- [ ] MFA 활성 사용자 시나리오 — `/verify-mfa` TOTP 부하
- [ ] `/oauth2/revoke` 시나리오 — admin revoke + Redis 블록리스트 부하
- [ ] JWK rotation 직후의 `jwks` 시나리오 (current + previous 둘 다 노출되는지)
