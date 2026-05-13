# OWASP API Security Top 10 (2023) — auth-service 매핑

본 IdP 의 endpoint / 코드를 OWASP API Top 10 2023 항목에 매핑하고, 각 항목별 현재
대응 / 코드 위치 / 회귀 테스트를 정리합니다. 본 문서는 운영 / 코드 변경 시 보안 가드가
누락되었는지 빠르게 점검하는 *checklist* 입니다.

## 요약

| # | 항목 | 상태 | 핵심 대응 |
| --- | --- | --- | --- |
| API1 | Broken Object Level Authorization (BOLA) | OK | `SessionController` 가 자기 자신의 (`tenantId`, `userId`) 컨텍스트로만 lookup |
| API2 | Broken Authentication | OK | RS256 + JWK rotation + refresh rotation + reuse detection + MFA TOTP |
| API3 | Broken Object Property Level Authorization | OK | DTO 가 `passwordHash` / `secretCipher` / `tokenHash` / client secret 노출 X |
| API4 | Unrestricted Resource Consumption | OK | `/login` `/register` `/refresh` 모두 IP / username 별 token bucket |
| API5 | Broken Function Level Authorization | OK | `@PreAuthorize` (`PERMISSION_admin:write`) + OPA `role.assign` 정책 |
| API6 | Unrestricted Access to Sensitive Business Flows | OK | 인증 없는 3개 endpoint 모두 rate limit. 추가 CAPTCHA 는 운영 ingress 단에서 결합 가능 |
| API7 | Server Side Request Forgery (SSRF) | OK | 외부 HTTP 호출 0건 (OPA 는 localhost sidecar, SMTP 는 config) |
| API8 | Security Misconfiguration | OK | HSTS / nosniff / frameOptions / Referrer-Policy 헤더 + Swagger 운영 노출 차단 |
| API9 | Improper Inventory Management | OK | 단일 `/api/v1/...` 버전, deprecated route 0개 |
| API10 | Unsafe Consumption of APIs | OK | OPA fail-closed + JWT 서명 검증 + Spring OIDC client 의 표준 흐름 |

---

## API1 — Broken Object Level Authorization (BOLA)

다른 사용자의 session / refresh token / role 에 접근할 수 있는가.

### 본 레포의 매핑

본 IdP 의 자체 endpoint 중 BOLA 위험이 있는 것은 `/api/v1/me/sessions/{id}` (내 세션 revoke)
하나입니다. RFC 7009 / 7662 endpoint 는 client_credentials 인증된 *client* 단위 호출이라 사용자
객체와 무관.

### 대응

`SessionController` 가 `AuthenticatedUser` (= JWT 의 sub + tnt) 만 resolver 로 받아
`RevokeSessionService` 로 위임. service 는 `RefreshTokenRepository.findActiveByUser(tenantId, userId)`
로 *본인의 active 세션만* 후보로 가져온 뒤 path 의 `sessionId` 가 그 안에 있는지 검사합니다 —
다른 사용자의 sessionId 를 path 에 넣어도 후보 자체에 안 들어옴 → `InvalidCredentials` 응답.

추가로 OPA `auth/session/revoke` 정책이 same-tenant / owner 만 허용 (admin escalation 은 별도
정책 경로).

### 코드 위치

- `auth-adapter-in/src/main/java/com/example/auth/adapter/in/rest/SessionController.java`
- `auth-application/src/main/java/com/example/auth/application/service/RevokeSessionService.java`
- `auth-adapter-out/src/main/java/com/example/auth/adapter/out/authz/EmbeddedPolicyDecisionAdapter.java#sessionRevoke`
- `policies/session_management.rego`

### 회귀 테스트

- `auth-application/src/test/java/com/example/auth/application/service/RevokeAndListSessionsServiceTest.java`
- `auth-adapter-out/src/test/java/com/example/auth/adapter/out/authz/OpaRegoEquivalenceTest.java` (Rego ↔ Java 동등성)

---

## API2 — Broken Authentication

본 레포의 *핵심*. JWT 검증 / JWK rotation / refresh reuse detection / OAuth2 흐름의 결함이 직접
공격 surface 가 됩니다.

### 본 레포의 매핑

- JWT 발급 — `NimbusAccessTokenIssuerAdapter` (RS256, kid 포함, jti UUID).
- JWT 검증 — `NimbusAccessTokenIntrospectorAdapter` + `JwtDecoder` 가 `JwkSourceProvider` 공유.
- JWK 회전 — `JwkRotationScheduler` (24h, ADR-0003) + `JwkSourceProvider` 의 grace (current + previous).
- Refresh rotation + reuse detection — `RefreshTokenService` (ADR-0004, ADR-0015).
- MFA TOTP — `VerifyMfaService` + `MfaChallengeStore` (1회 consume).
- Login 정보 누설 차단 — bad creds / locked / not-found 모두 같은 응답 (`LoginService`).
- Refresh / login / register 모두 IP 기반 rate limit (token bucket).

### 회귀 테스트

- JWT 검증: `e2e-tests/.../IntrospectionE2eTest.java`, `JwksAndOidcDiscoveryE2eTest.java`.
- JWK rotation: `e2e-tests/.../JwkRotationE2eTest.java` (grace 안 두 키 모두 검증 통과).
- Refresh reuse + grace: `auth-application/.../RefreshTokenServiceTest.java`,
  `e2e-tests/.../RegisterAndLoginE2eTest.java`.
- MFA: `auth-application/.../VerifyMfaServiceTest.java`, `e2e-tests/.../MfaFlowE2eTest.java`.
- Login fail-uniform: `auth-application/.../LoginServiceTest.java`.

---

## API3 — Broken Object Property Level Authorization

DTO 의 sensitive field (password hash, client secret, refresh token hash) 가 응답에 새는지.

### 본 레포의 매핑

- `RegisterResponse` 는 `userId` 만 노출.
- `TokenResponse` 는 access + refresh 평문 (의도된 응답) + ttl. 다른 사용자 정보 0.
- `SessionResponse` 는 sessionId / deviceLabel / ipAddress / timestamps — refresh hash 는 노출 안 함.
- `IntrospectionController` 는 RFC 7662 §2.2 만 — token 평문 / passwordHash 등 절대 노출 안 함.
- `UserEntity#toDomain` 의 결과를 controller 가 받아 변환할 때 비밀 필드를 절대 직접 직렬화 안 함
  (DTO 통과 강제).

### 회귀 테스트

- DTO 정의 자체가 lock — `RegisterResponse.java` / `SessionResponse.java` / `TokenResponse.java` 의
  필드 목록.
- `auth-application/.../IntrospectTokenServiceTest.java` (active=false 시 다른 필드 노출 X).
- README 의 "보안 점검 항목" 단락에 도메인 객체 `toString` 안전성 명시 (코드 리뷰 시 가드).

---

## API4 — Unrestricted Resource Consumption

미인증 endpoint 의 brute-force / 자원 소진 시도를 어떻게 막는가.

### 본 레포의 매핑

bucket4j-lettuce 기반 분산 token bucket (`RedisRateLimiterAdapter`) 으로 세 미인증 endpoint 모두
보호합니다. 같은 bucket 설정 (`auth.login-rate-burst` / `auth.login-rate-window`, 기본 10 req/min)
을 *다른 key 접두사* 로 분리.

| Endpoint | Rate key | 의도 |
| --- | --- | --- |
| `POST /api/v1/auth/login` | `login:<tenant>:<ip>:<email>` | 사용자별 brute-force 차단 |
| `POST /api/v1/auth/register` | `register:<tenant>:<ip>` | bot 자동 가입 / account enumeration 차단 |
| `POST /api/v1/auth/refresh` | `refresh:<ip>` | refresh token 추측 / DoS 차단 |

`/oauth2/introspect` 는 client_credentials 인증된 client 만 호출 가능 (RFC 7662) — 인증 단계
자체가 1차 throttle. 추가로 *Resource Server 측 cache TTL 10초* 가이드를 README 에 명시
(왕복 비용 감소 + admin revoke SLA 균형).

`/oauth2/revoke` 도 같은 방식. 추가로 OPA `auth/token/revoke` 정책이 scope 가드.

### 코드 위치

- `auth-application/src/main/java/com/example/auth/application/service/LoginService.java`
- `auth-application/src/main/java/com/example/auth/application/service/RegisterUserService.java`
- `auth-application/src/main/java/com/example/auth/application/service/RefreshTokenService.java`
- `auth-adapter-out/src/main/java/com/example/auth/adapter/out/redis/RedisRateLimiterAdapter.java`

### 회귀 테스트

- `auth-application/.../LoginServiceTest.java#rate_limit_차단_시_RateLimited_예외_그리고_audit`
- `auth-application/.../RegisterUserServiceTest.java#IP_있을_때_rate_limit_차단_시_…`
- `auth-application/.../RefreshTokenServiceTest.java#IP_있을_때_rate_limit_초과_시_RateLimited_예외`

---

## API5 — Broken Function Level Authorization

`/api/v1/admin/**` 같은 관리자 endpoint 가 일반 사용자로 호출되지 않도록 보호되는가.

### 본 레포의 매핑

2단계 방어:

1. **RBAC (Spring Security `@PreAuthorize`)** — `AdminController#assignRole` 가
   `hasAuthority('PERMISSION_admin:write')` 요구. JWT 의 `permissions` claim 으로 강제.
2. **ABAC (OPA `auth/role/assign`)** — 같은 admin 권한 안에서도 *어떤 role* 을 부여할 수 있는지
   세분화. admin role 부여는 senior_admin 보유자만, cross-tenant 부여는 global_admin 만.

`SecurityConfig` 가 chain 3개로 분리:
- order 0 — `/oauth2/introspect` `/oauth2/revoke` (HttpBasic, RegisteredClient).
- order 1 — Spring Authorization Server endpoint.
- order 2 — `/api/v1/me/**` `/api/v1/admin/**` (JWT resource server).
- order 3 — public (`/api/v1/auth/**`, `/actuator/**`, `/swagger-ui/**`, `/.well-known/**`) +
  `anyRequest().denyAll()` (fall-through 차단).

### 코드 위치

- `auth-adapter-in/src/main/java/com/example/auth/adapter/in/rest/AdminController.java`
- `auth-bootstrap/src/main/java/com/example/auth/bootstrap/security/SecurityConfig.java`
- `auth-application/src/main/java/com/example/auth/application/service/AssignRoleService.java`
- `policies/role_assignment.rego`

### 회귀 테스트

- `auth-application/.../AssignRoleServiceTest.java`
- `auth-adapter-out/.../OpaRegoEquivalenceTest.java`
- `auth-bootstrap/.../ApplicationContextSmokeTest.java` (chain 부팅 확인)

---

## API6 — Unrestricted Access to Sensitive Business Flows

login bot / signup 자동화 같은 *합법적인 흐름의 자동화 남용*.

### 본 레포의 매핑

- `register` / `login` / `refresh` 의 rate limit 자체가 1차 가드 (API4 참조).
- 추가 가드는 운영 ingress / WAF 단에서 CAPTCHA (예: hCaptcha) / device fingerprint 와 결합 가능
  하도록 endpoint 가 idempotent 한 JSON 응답 형식을 유지합니다.
- audit log (`AuditLoginAttemptsService`) 가 `LOGIN_FAILED_RATE_LIMITED`,
  `LOGIN_FAILED_BAD_CREDENTIALS` 등을 append-only 로 적재 — SIEM (`security-log-search`) 에서
  IP / 사용자 단위 이상 패턴 탐지.

### 코드 위치

- 위 API4 의 rate limit 흐름 + `auth-application/.../AuditLoginAttemptsService.java`.

### 회귀 테스트

- API4 와 동일.

---

## API7 — Server Side Request Forgery (SSRF)

본 IdP 가 외부 URL 을 호출하는 경로가 있는가, 있다면 사용자 입력이 URL 에 들어가는가.

### 본 레포의 매핑

- **OPA sidecar 호출** — `OpaRestPolicyDecisionAdapter` 가 `RestClient` 로 OPA daemon 에 호출하지만
  `baseUrl` 은 `auth.opa.base-url` 설정 (운영 권장 `http://localhost:8181`) 에서만 옵니다 —
  사용자 입력이 직접 URL 에 합쳐지지 않습니다. 정책 path 도 application 내부 상수 (`auth/session/revoke`
  같은 코드 리터럴) 만 전달.
- **SMTP** — `SmtpVerificationMailSenderAdapter` 가 `JavaMailSender` 위임. host / port 는
  `spring.mail.*` 설정에서만. email *수신자* 는 사용자 입력이지만 이건 mail 의 본질이고 SSRF 와 무관.
- **OIDC consumer** — Spring Security 의 `OidcUserService` 가 Google 의 well-known userinfo
  endpoint 만 호출 — registration metadata (`spring.security.oauth2.client.registration.google.*`)
  에서 정의된 URL 만 호출.

따라서 *사용자 입력에 의해 임의 URL 이 호출되는 경로는 0개*.

### 회귀 테스트

- `OpaRestPolicyDecisionAdapter` 단위 테스트 (간단 timeout / fail-closed 검증).
- 새로운 외부 HTTP 호출이 추가되면 본 항목 갱신 + URL allowlist 도입 검토.

---

## API8 — Security Misconfiguration

CORS / HSTS / CSP / default password / Swagger 운영 노출 등.

### 본 레포의 매핑

- **응답 헤더** — `SecurityConfig#applyBaselineHeaders` 가 모든 chain 에 적용:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains` (HSTS 1년)
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
  - `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` (Spring 기본)
- **CORS** — 본 IdP 가 직접 처리하지 않음. 호출자는 같은 origin 또는 ingress / API gateway 가
  통합 관리. 잘못된 wildcard CORS 가 IdP attack surface 가 되는 것을 의도적으로 회피.
- **Swagger UI / OpenAPI 운영 노출** — `springdoc.api-docs.enabled` / `swagger-ui.enabled` 가
  `${AUTH_OPENAPI_ENABLED:false}` — *기본 false*. dev / e2e 만 true. helm prod values 에서도
  `AUTH_OPENAPI_ENABLED=false` 강제.
- **default password** — `application.yml` 에 평문 placeholder 만 두고 운영 환경변수 / k8s Secret
  으로 강제 override. helm `values.yaml` 의 `REPLACE_AT_DEPLOY_TIME` 마커 + `NOTES.txt` 가
  배포 시 경고.
- **OAuth2 client 의 client_secret** — `{noop}<plain>` 으로 in-memory 등록 (dev). 운영 전환 시
  `{bcrypt}` prefix + `BCryptPasswordEncoder` 로 교체 권장 (코드 주석에 명시,
  `AuthorizationServerClientsConfig`).
- **JWK 평문 저장 금지** — `LocalFileKeyMaterialSource` 는 dev/local 만. 운영은 `KmsKeyMaterialSource`
  (ADR-0014). master key 도 환경변수 / Vault / KMS.
- **trusted-proxies 기본 빈 목록** — X-Forwarded-For 위조 차단 (별도 ADR-0011 분과). 운영자가
  명시적으로 사내 LB CIDR 만 등록.

### 코드 위치

- `auth-bootstrap/src/main/java/com/example/auth/bootstrap/security/SecurityConfig.java`
  (`applyBaselineHeaders`)
- `auth-bootstrap/src/main/resources/application.yml`
- `helm/auth-service/values-prod.yaml`

### 회귀 테스트

- `auth-bootstrap/.../ApplicationContextSmokeTest.java` (chain 부팅 / 헤더 빈 적용).
- `auth-adapter-in/.../ClientIpResolverTest.java` (trusted-proxies 위조 차단).
- `e2e-tests/.../OpenApiSpecE2eTest.java` (운영 OFF 시 spec 미노출 분기는 application-e2e.yml 의
  on/off 토글로 확인).

---

## API9 — Improper Inventory Management

deprecated / shadow / 더이상 사용하지 않는 endpoint, API 버전 관리 부재.

### 본 레포의 매핑

- 단일 API 버전 `/api/v1/...` — `/api/v2/...` deprecation 흐름은 본 시점 미사용.
- OAuth2 / OIDC 표준 endpoint (`/oauth2/token`, `/oauth2/jwks`, `/.well-known/openid-configuration`,
  `/oauth2/introspect`, `/oauth2/revoke`) — 각각 RFC 가 명시.
- `Backstage catalog-info.yaml` 로 service / endpoint 인벤토리 메타데이터 노출.
- README + ADR 18개로 모든 활성 결정을 문서화 — deprecated 가 생기면 ADR superseded 표시.

### 회귀 테스트

- `e2e-tests/.../OpenApiSpecE2eTest.java` — spec 의 path 목록을 회귀 락다운. 새 endpoint 추가 /
  제거 시 spec 검증이 깨져 의식적 갱신 강제.

---

## API10 — Unsafe Consumption of APIs

본 IdP 가 *호출하는* 외부 API 의 응답을 그대로 신뢰하면 안 됨.

### 본 레포의 매핑

- **OPA daemon 응답** — `OpaInputMarshaller#parseResponse` 가 응답 shape 를 검증.
  `result` 누락 / non-boolean / non-object 모두 fail-closed (deny).
- **OPA 호출 실패** — `OpaRestPolicyDecisionAdapter` 가 `ResourceAccessException` (네트워크 /
  timeout) / 일반 `RuntimeException` 모두 deny 로 감싸 반환. 정책 엔진이 죽으면 모든 권한 부여가
  자동 차단.
- **외부 IdP 사용자 응답 (Google OIDC)** — Spring Security 의 `OidcUserService` 가 OIDC 표준
  검증 (id_token 서명, nonce, exp). 본 IdP 의 `LinkOrCreateUserFromOidcService` 는 검증된 sub +
  email 만 받아 도메인 매핑. 원본 응답을 그대로 신뢰하지 않음.
- **외부 JWT 토큰 introspect** — `NimbusAccessTokenIntrospectorAdapter` 가 본 IdP 의 JwkSource
  로 서명을 검증해 *외부 issuer* 의 토큰은 자동 inactive 처리. RFC 7662 §2.2 의 "token not found"
  와 동등.

### 코드 위치

- `auth-adapter-out/src/main/java/com/example/auth/adapter/out/authz/OpaRestPolicyDecisionAdapter.java`
- `auth-adapter-out/src/main/java/com/example/auth/adapter/out/authz/OpaInputMarshaller.java`
- `auth-bootstrap/src/main/java/com/example/auth/bootstrap/oidc/OidcLoginAdapterConfig.java`

### 회귀 테스트

- `auth-adapter-out/.../OpaRegoEquivalenceTest.java` — 21 case 의 Rego ↔ embedded 동등성.
- `auth-application/.../LinkOrCreateUserFromOidcServiceTest.java`.

---

## 변경 이력

- 2026-05-13 — 신규 작성. API4 / API8 의 새 가드 추가 (`register` / `refresh` rate limit, baseline
  보안 헤더) 와 함께.
