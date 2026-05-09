# ADR-0005: RBAC vs ABAC — 본 ADR 는 RBAC, ABAC 는 후속

## 상태
적용

## 배경
인가 모델 선택지:

- **RBAC** (Role-Based Access Control) — User → Role → Permission. 단순하고 운영자가
  이해하기 쉬움. 대신 "조건부" 권한 (예: 본인 데이터만, 특정 시간만) 을 표현하기 어려움.
- **ABAC** (Attribute-Based Access Control) — 정책 = 속성 함수. 유연하지만 정책 엔진
  (OPA, Casbin 등) 도입 + 모든 service 가 같은 평가기를 써야 하는 운영 부담.
- **ReBAC** (Relationship-Based) — Zanzibar / SpiceDB 류. 그래프 기반. 본 시점 도입은
  과함.

## 결정
**RBAC 로 시작**. JWT claim 에 `roles` + `permissions` 를 박제 — consumer service 는 별도
권한 lookup 없이 인가 결정.

구조:
- `User` → `user_roles` (m:n) → `Role` → `role_permissions` (m:n) → `Permission`.
- `Permission` 형식 = `resource:action` (예: `billing:read`, `admin:write`).
- JWT 의 `permissions` 는 사용자가 가진 모든 role 의 permission 합집합 — consumer 는
  `hasAuthority('PERMISSION_billing:read')` 한 번으로 결정.

## 결과
- consumer 측 인가 코드가 단순 (Spring Security `@PreAuthorize` 한 줄).
- role / permission 변경이 사용자가 다음 토큰을 받기 전까지 반영되지 않음 (access token
  TTL 15분 = 권한 변경의 최대 지연).
- (단점) 조건부 권한 (예: "본인 게시물만 수정") 은 RBAC 만으로 안 됨 — 그 부분은
  consumer 의 도메인 코드가 별도 검증.
- (단점) tenant 가 늘어나면서 role 종류가 폭증 (테넌트 X 역할) 하면 JWT 크기가 커지고
  관리가 힘들어짐 — 그 시점에 ABAC / ReBAC 도입 검토.

## 다시 검토할 시점
- 권한 정책에 시간 / 위치 / 데이터 속성 조건이 들어와야 할 때 → ABAC 의 OPA / Casbin
  도입 (별도 ADR).
- 한 테넌트 안에서 사용자가 수십 개 role 을 동시에 갖는 시나리오 (대형 B2B) → ReBAC.
