# ADR-0006: Multi-tenant 격리 — JWT claim + query filter

## 상태
적용

## 배경
한 instance 가 여러 테넌트를 호스팅. 한 테넌트의 사용자가 다른 테넌트 데이터를 보거나
수정할 수 있으면 사고는 *치명적* (대량 PII 노출).

격리 선택지:

- **DB-level 분리** — 테넌트마다 다른 DB 또는 스키마. 가장 강한 격리. 단 운영 / 마이그레이션
  비용 폭증.
- **PostgreSQL RLS (Row Level Security)** — DB 가 row 단위로 강제. 강하지만 모든 query 에
  `SET LOCAL app.tenant_id = ...` 강제 + JPA / JOOQ 와 미세하게 깨지는 지점이 있음.
- **Application-level filter** — 모든 query 에 `WHERE tenant_id = ?` 조건. 코드 검증이
  핵심.

## 결정
**Application-level filter + JWT 의 `tnt` claim 강제**.

- access JWT 에 `tnt` claim (= tenantId UUID) 박제.
- `AuthenticatedUser` 에 `tenantId` 포함, 모든 controller / use case 가 첫 인자로 받음.
- `UserRepository.findById(tenantId, userId)`, `findActiveByUser(tenantId, userId)` —
  port signature 가 tenantId 강제. tenant-blind lookup 메서드는 *추가 금지*.
- DB 측에서는 `(tenant_id, ...)` unique 제약 + tenant_id 인덱스로 조회 성능 확보.

## 다시 검토할 시점
- 단일 테넌트의 데이터량이 너무 커서 다른 테넌트 query 에 영향 (noisy neighbor) → PG
  파티셔닝 또는 DB 분리.
- 보안 사고가 한 번이라도 cross-tenant 누설로 이어진 경우 → 즉시 PG RLS 추가 도입.

## 결과
- 한 query 의 tenant_id 누락이 보안 사고 — code review / linter rule (port signature 가
  강제) 로 1차 방어, audit log 의 tenant_id mismatch 통계로 사후 감지.
- (단점) DB 가 막아주는 것이 아니므로 리뷰가 곧 보안. PG RLS 가 더 강함.
- (단점) 운영 batch / migration 스크립트 작성자가 tenant_id 를 빼먹기 쉬움 — 별도 review
  체크리스트 필요.
