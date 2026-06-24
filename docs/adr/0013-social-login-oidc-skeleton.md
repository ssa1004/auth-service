# ADR-0013: Social Login (Google OIDC consumer) skeleton

## 상태
적용 (Google 만 wiring, 다른 vendor 는 같은 패턴 확장)

## 배경
사용자가 Google / Microsoft / GitHub 계정으로 로그인할 수 있게 합니다. 직접 비밀번호
흐름과 공존해야 하고, 같은 사용자가 두 방식을 모두 사용할 수 있어야 합니다.

설계 포인트:

- **외부 매핑** — IdP 측 user 의 sub (예: Google numeric ID) 를 진실로 잡습니다. 이메일은
  IdP 에서 변경 가능하므로 매핑 키로 부적합합니다.
- **자동 가입** — 처음 OIDC 로 로그인하는 사용자가 사용자 도메인에 없으면 자동 생성.
  비밀번호 컬럼이 NOT NULL 이라 랜덤 비밀번호 해시를 채워 넣고, 사용자가 OIDC 외 로그인을
  하지 못하도록 합니다.
- **link to existing** — 같은 테넌트에 같은 이메일의 기존 사용자가 있으면 새 사용자가
  아니라 기존 사용자에 외부 매핑만 추가합니다.
- **multi-tenant** — OIDC redirect URI 또는 state 파라미터로 tenantSlug 전달. 본 단계는
  `auth.oidc.default-tenant-slug` 한 개로만 wiring (skeleton).

## 결정

### 데이터
V3 마이그레이션 — `external_identities` 테이블:
- `(provider, provider_user_id)` UNIQUE — 같은 IdP 계정이 두 사용자에 매달림 차단.
- `user_id` FK → `users(id)` ON DELETE CASCADE — 사용자 삭제 시 외부 매핑도 같이.
- `email_at_link` — 가입 시점 이메일 (추적용. 매핑은 sub 기준).
- `linked_at` / `last_login_at`.

### 도메인
- `ExternalIdentity` — record-like 도메인 객체.
- `ExternalProvider` enum — `GOOGLE`, `MICROSOFT`, `GITHUB` (확장 여지).

### Application
- `LinkOrCreateUserFromOidcUseCase` — 인풋: `tenantSlug, provider, providerUserId, email`.
- 매핑 우선순위:
  1. `(provider, providerUserId)` 외부 매핑 → 기존 user, `last_login_at` touch.
  2. 같은 테넌트 + 이메일 사용자 → 외부 매핑만 추가.
  3. 자동 가입 — 랜덤 비밀번호 해시 + verified 상태로 저장.

### Infra (Spring Security oauth2-client)
- `spring-boot-starter-oauth2-client` 의존 추가.
- `OidcLoginAdapterConfig` — `OidcUserService` 빈으로 감싸서 Google userinfo 응답을
  use case 로 전달.
- `OidcLoginSecurityConfig` — order=0 SecurityFilterChain — `/oauth2/authorization/**`,
  `/login/oauth2/code/**` 매칭, `oauth2Login()` 활성.
- 두 config 모두 `@ConditionalOnProperty(spring.security.oauth2.client.registration.google.client-id)`
  → 미설정 시 비활성, 기존 SecurityConfig 영향 없음 (테스트 통과).

## 결과
- Google OIDC 로그인 동선이 `/oauth2/authorization/google` 한 줄로 가능.
- 같은 이메일 사용자에 자동 link → 사용자가 비밀번호 / OIDC 둘 다 사용 가능.
- 다른 IdP 도입은 `ExternalProvider` enum 추가 + Spring Security 측 registration 설정만.

## 다시 검토할 시점
- multi-tenant 가 본격화되면 redirect URI 에 tenantSlug 를 포함 (`/oauth2/authorization/{tenant}/google`).
- IdP 응답에 이메일이 없는 케이스 (GitHub privacy 설정) → 사용자에게 추가 입력 흐름.
- `AuditEventType.OIDC_LINKED` / `OIDC_AUTO_REGISTERED` 별도 enum 추가 (현재는 USER_REGISTERED 재사용).

## 용어 풀이 (쉽게)

- **OIDC (OpenID Connect)** — 'Google 계정으로 로그인' 같은 걸 표준으로 만든 규약. 우리 서비스가 비밀번호를 직접 받지 않고, 구글이 대신 본인 확인을 해주고 그 결과를 받아온다.
- **IdP (Identity Provider, 신원 공급자)** — 신분 확인을 대신 해주는 외부 기관(여기선 Google·Microsoft·GitHub). 사용자는 거기에 로그인하고 우리는 그 결과만 믿는다.
- **sub (subject 클레임)** — IdP가 사용자마다 매기는 '절대 안 바뀌는 고유 번호'. 이메일은 사용자가 바꿀 수 있어 매핑 키로 부적합해서, 변하지 않는 sub를 진짜 기준으로 삼는다.
- **link / 자동 가입 (account linking)** — 같은 이메일의 기존 사용자가 있으면 새 계정을 또 만들지 않고 그 사용자에 'Google 계정 매핑'만 덧붙이는 것. 한 사람이 비밀번호·OIDC 둘 다 쓸 수 있게 된다.
