# ADR-0006: Multi-tenant 격리 — JWT claim + query filter

## 상태
적용

## 배경
한 instance 가 여러 테넌트를 호스팅합니다. 한 테넌트의 사용자가 다른 테넌트 데이터를
보거나 수정할 수 있게 되면 사고가 치명적이 됩니다 (대량 PII 노출).

격리 선택지:

- **DB-level 분리** — 테넌트마다 다른 DB 또는 스키마. 가장 강한 격리지만 운영 /
  마이그레이션 비용이 큽니다.
- **PostgreSQL RLS (Row Level Security)** — DB 가 row 단위로 강제. 강하지만 모든 query 에
  `SET LOCAL app.tenant_id = ...` 가 필요하고 JPA / JOOQ 와 미세하게 깨지는 지점이
  있습니다.
- **Application-level filter** — 모든 query 에 `WHERE tenant_id = ?` 조건을 두고 코드
  검증이 핵심.

## 결정
Application-level filter + JWT 의 `tnt` claim 강제.

- access JWT 에 `tnt` claim (= tenantId UUID) 을 담습니다.
- `AuthenticatedUser` 에 `tenantId` 포함, 모든 controller / use case 가 첫 인자로 받습니다.
- `UserRepository.findById(tenantId, userId)`, `findActiveByUser(tenantId, userId)` 처럼
  port signature 자체가 tenantId 를 강제. tenant 무관한 lookup 메서드는 추가 금지.
- DB 측에서는 `(tenant_id, ...)` unique 제약 + tenant_id 인덱스로 조회 성능을 확보합니다.

## 결과
- 한 query 의 tenant_id 누락이 곧 보안 사고. code review / linter rule (port signature 가
  강제) 로 1차 방어, audit log 의 tenant_id mismatch 통계로 사후 감지합니다.
- (단점) DB 가 막아주는 것이 아니므로 리뷰가 곧 보안. PG RLS 가 더 강합니다.
- (단점) 운영 batch / migration 스크립트 작성자가 tenant_id 를 빼먹기 쉬워 별도 review
  체크리스트가 필요합니다.

### 시나리오: cross-tenant 조회 시도
공격자가 자기 테넌트의 access token 으로 다른 테넌트 user UUID 를 직접 호출.
`UserRepository.findById(tenantId, otherTenantUserId)` signature 가 tenantId 를 첫 인자로
받기 때문에 query 의 `WHERE tenant_id = ? AND id = ?` 가 매칭되지 않아 결과가 비어 404
가 떨어집니다. token tampering 은 JWT 서명 검증에서 차단됩니다.

## 다시 검토할 시점
- 단일 테넌트의 데이터량이 너무 커서 다른 테넌트 query 에 영향 (noisy neighbor) → PG
  파티셔닝 또는 DB 분리.
- 보안 사고가 한 번이라도 cross-tenant 누설로 이어진 경우 → 즉시 PG RLS 추가 도입.

## 용어 풀이 (쉽게)

- **멀티테넌트 격리 (multi-tenant)** — 한 서버에 여러 회사(테넌트)가 같이 사는데 A사가 B사 데이터를 절대 못 보게 치는 칸막이. 모든 조회에 'tenant_id가 같을 때만'을 강제로 붙인다.
- **PostgreSQL RLS (Row Level Security, 행 단위 보안)** — DB가 직접 '너는 네 회사 행만'이라고 모든 쿼리에 조건을 끼워 넣는 기능. 개발자가 WHERE를 깜빡해도 DB가 막아줘 가장 강하다.
- **Application-level filter (앱 단 필터)** — DB 대신 애플리케이션 코드가 모든 쿼리에 `WHERE tenant_id = ?`를 붙여 격리하는 방식. 가볍지만 코드 한 줄 실수가 곧 보안 사고라 리뷰가 곧 방어선이 된다.
- **noisy neighbor (시끄러운 이웃)** — 한 테넌트의 데이터·트래픽이 너무 커서 같은 서버에 사는 다른 테넌트 성능까지 끌어내리는 현상. 윗집이 시끄러우면 아랫집까지 잠 못 자는 셈.
- **PII (개인 식별 정보)** — 이름·이메일·주민번호처럼 사람을 특정할 수 있는 민감 정보. 테넌트가 섞여 새면 대량 PII 유출 사고가 된다.
