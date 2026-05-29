# 백엔드 스킬 인덱스 — 이 레포에서 무엇을 배우나

> 이 레포(OAuth2 / OIDC IdP)가 시연하는 백엔드 / 보안 패턴을
> **"무엇 → 이 레포 어디서 → 왜(ADR) → 더 깊은 이론"** 으로 잇는 학습용 인덱스.
> "이 패턴 공부하려면 어디부터 보나"의 진입점. 설명을 다시 쓰지 않고 코드·결정·이론으로 연결만 한다.
>
> 짝 학습 레포: [dev-lab](https://github.com/ssa1004/dev-lab) (이론) ↔ 이 레포 (구현).
> 이론에서 "왜"를, 여기서 "실제로 어떻게"를 본다.

## 토큰 발행 · 서명 (OAuth2 / OIDC)

| 패턴 | 이 레포 어디서 | 왜 (ADR) | 한 줄 |
|------|---------------|---------|-------|
| **Spring Authorization Server 1.4** | `auth-adapter-in` REST + `auth-bootstrap` 의 `SecurityFilterChain` 조립 | [ADR-0001](adr/0001-hexagonal-and-spring-authorization-server.md) | `/oauth2/token`·`/oauth2/jwks`·`/.well-known/openid-configuration` 자동 노출 + 자체 first-party endpoint 공존 |
| **RS256 JWT 서명** | `auth-adapter-out/.../security/JwkSourceProvider.kt` (Nimbus JOSE) | [ADR-0002](adr/0002-rs256-vs-eddsa.md) | self-contained 토큰 — Resource Server 가 IdP 왕복 없이 검증 |
| **JWK rotation (24h + 1 cycle grace)** | `auth-bootstrap/.../jwk/JwkRotationScheduler.kt`, `JwkConfig.kt` + `JwkSourceProvider.kt` (`AtomicReference<List<JWK>>`, current+previous) | [ADR-0003](adr/0003-jwk-rotation-strategy.md) | 키 유출 영향 범위를 시간으로 제한. 직전 키 verify-only 유지로 회전 직후 401 폭주 차단 |
| **key material 외부화 추상화** | `auth-application/.../port/out/KeyMaterialSource.kt` (port) ↔ `LocalFileKeyMaterialSource.kt` / `KmsKeyMaterialSource.kt` (adapter) | [ADR-0014](adr/0014-key-material-source-abstraction.md) | dev 는 파일 영속, prod 는 KMS / Vault. JDK `KeyPair` 만 노출해 도메인이 KMS SDK 비의존 |

→ 이론: `dev-lab/api-design` (OAuth2 / OIDC / JWT, 인증 vs 인가, RFC 표준), `dev-lab/vault` (key / secret rotation, JWK, KMS transit)

## 세션 · refresh 토큰 수명주기

| 패턴 | 이 레포 어디서 | 왜 (ADR) | 한 줄 |
|------|---------------|---------|-------|
| **refresh rotation + reuse detection** | `auth-application/.../service/RefreshTokenService.kt`, `auth-domain/.../token/RefreshToken.kt` + `RefreshTokenStatus.kt` | [ADR-0004](adr/0004-refresh-token-rotation-and-reuse-detection.md) | 회전된 token 재사용 → 사용자 전 세션 일괄 revoke. 탈취를 자동 탐지 (RFC 6749 §10.4) |
| **평문 토큰 비저장 (SHA-256 hash only)** | `RefreshTokenRepositoryAdapter.kt` (`findByTokenHashForUpdate`, 비관적 잠금) | ADR-0004 | 평문은 DB / 로그 / audit 어디에도 없음. 256bit CSPRNG 라 BCrypt 불필요 |
| **reuse grace window (5초 + 같은 IP)** | `RefreshToken.isWithinReuseGrace(...)` + `RefreshTokenService` | [ADR-0015](adr/0015-refresh-reuse-grace-window.md) | 정상 mobile retry 는 보호, IP 다른 회전 직후 사용은 즉시 reuse 로 처리 — 보안과 UX 의 trade-off |

→ 이론: `dev-lab/api-design` (refresh token 패턴, 토큰 수명), `dev-lab/redis` (refresh hash / 블록리스트 / rate-limit 저장), `dev-lab/distributed-systems` (동시 retry race + 비관적 잠금)

## 인가 (RBAC → ABAC)

| 패턴 | 이 레포 어디서 | 왜 (ADR) | 한 줄 |
|------|---------------|---------|-------|
| **RBAC** (User → Role → Permission) | JWT claim 에 `roles` + `permissions` 적재 (`resource:action`) | [ADR-0005](adr/0005-rbac-vs-abac.md) | consumer 가 별도 lookup 없이 `hasAuthority(...)` 한 줄로 인가 결정 |
| **ABAC — OPA Rego (PDP)** | `auth-application/.../authz/PolicyDecisionPort.kt` ↔ `EmbeddedPolicyDecisionAdapter.kt` / `OpaRestPolicyDecisionAdapter.kt`; 정책은 `policies/*.rego` | [ADR-0016](adr/0016-opa-policy-decision.md) | 정책을 코드 밖으로 — 본인 자원만 / 테넌트 격리 / senior_admin 만 부여 등 상황별 정책을 Rego 로 |
| **embedded / sidecar 두 모드 + fail-closed** | `auth-bootstrap/.../authz/PolicyDecisionConfig.kt` (`@ConditionalOnProperty`) | ADR-0016 | dev 는 in-process, prod 는 OPA sidecar. 평가 실패는 deny (권한 불확실 시 거절) |
| **multi-tenant 격리** | JWT `tnt` claim + 모든 query tenant_id 강제, `policies/tenant_isolation.rego` | [ADR-0006](adr/0006-multi-tenant-data-isolation.md) | cross-tenant 접근 차단을 RBAC(claim) + ABAC(정책) 두 단계로 |

→ 이론: `dev-lab/api-design` (인증 vs 인가, RBAC / ABAC / ReBAC), `dev-lab/system-design` (PDP / PEP 분리, 정책 외부화)

## 토큰 강제 종료 (RFC 표준)

| 패턴 | 이 레포 어디서 | 왜 (ADR) | 한 줄 |
|------|---------------|---------|-------|
| **Token Introspection (RFC 7662)** | `auth-adapter-in/.../rest/IntrospectionController.kt`, `auth-application/.../service/IntrospectTokenService.kt` | [ADR-0017](adr/0017-token-introspection-rfc-7662.md) | 외부 issuer / 가짜 / revoke 모두 `{active:false}` (정보 누설 차단). client_secret_basic 인증 강제 (토큰 oracle 방지) |
| **Token Revocation (RFC 7009)** | `auth-adapter-in/.../rest/RevokeTokenController.kt`, `auth-application/.../service/RevokeTokenByAdminService.kt` | [ADR-0018](adr/0018-token-revocation-rfc-7009.md) | admin 강제 revoke. access JWT → Redis 블록리스트(잔여 TTL), refresh → `REVOKED_BY_ADMIN`. 권한은 `policies/token_revocation.rego` 한 줄 |
| **self-validate vs introspect 의 SLA** | Resource Server 측 10초 cache 권장 (README "Resource Server 측 introspection 가이드") | ADR-0017 | self-contained JWT 의 한계(발행 후 강제 종료)를 introspect + 블록리스트로 보완. 차단 SLA ≤ 10초 |

→ 이론: `dev-lab/api-design` (RFC 7662 / 7009, self-contained vs reference token), `dev-lab/redis` (jti 블록리스트 + TTL 자동 정리)

## 보안 자료 보호 · 감사

| 패턴 | 이 레포 어디서 | 왜 (ADR) | 한 줄 |
|------|---------------|---------|-------|
| **TOTP 2FA (RFC 6238)** | `auth-adapter-out` 의 TOTP + AES-GCM secret 암호화, `VerifyMfaUseCase` (challenge 1회 consume) | [ADR-0007](adr/0007-mfa-totp-vs-sms-webauthn.md) | secret 평문은 도메인에 없음 (`secretCipher` 만). master key 는 env / KMS. replay 차단 |
| **append-only audit log** | `AuditLoginAttemptsUseCase` (`REQUIRES_NEW` — 호출 트랜잭션 rollback 무관) | [ADR-0008](adr/0008-audit-log-append-only.md) | 보안 사고 사후 분석. 평문 비밀 / 토큰은 절대 미적재 (호출자 마스킹 책임) |
| **정보 누설 차단 로그인** | `LoginUseCase` (bad credentials / locked / not-found 동일 응답) | — | 계정 존재 여부 oracle 차단. 도메인 객체 `toString` 도 평문 / hash 미노출 |
| **rate limit (brute-force 차단)** | bucket4j-lettuce CAS, `(IP, tenant, email)` 키 | — | Redis 원자 연산으로 분산 환경 rate limit |

→ 이론: `dev-lab/api-design` (MFA / TOTP, OWASP 인증 취약점), `dev-lab/vault` (대칭 키 관리 / 암호화), `dev-lab/observability` (audit / SIEM, 보안 이벤트 추적)

## 헥사고날 · 운영 (SRE)

| 패턴 | 이 레포 어디서 | 왜 (ADR) | 한 줄 |
|------|---------------|---------|-------|
| **헥사고날 (ports & adapters)** | 6개 모듈 — `auth-domain`(Spring 의존 0) / `auth-application`(use case + port) / `auth-adapter-in` / `auth-adapter-out` / `auth-bootstrap` / `e2e-tests` | [ADR-0001](adr/0001-hexagonal-and-spring-authorization-server.md) | 라이브러리 교체(BCrypt→Argon2, Spring AS→자체 JWS)가 adapter 안에서 끝남. 도메인 테스트는 ms 단위 |
| **HikariCP 튜닝 + leak detection** | DataSource 설정 | [ADR-0009](adr/0009-hikaricp-tuning-and-leak-detection.md) | 커넥션 풀 포화 / 누수 조기 검출 |
| **K8s 3종 probe + readiness coordinator** | `infrastructure/k8s/`, `helm/auth-service/` | [ADR-0010](adr/0010-k8s-three-probes-and-readiness-coordinator.md) | liveness / readiness / startup 분리로 기동 / 재기동 안정화 |
| **graceful shutdown (SIGTERM)** | `auth-bootstrap` | [ADR-0011](adr/0011-graceful-shutdown.md) | in-flight 요청 처리 후 종료 — 무중단 배포 |

→ 이론: `dev-lab/system-design` (헥사고날 / 모듈 경계), `dev-lab/resilience` (커넥션 풀 / 타임아웃 / fail-closed), `dev-lab/observability` (probe / SLO / 무중단 배포)

## 학습 순서 제안 (이 레포 기준)

1. **[README](../README.md) 빠른 시작** → `make up` / `make run` / `make demo` 로 발행 → introspect → revoke 흐름 감 잡기
2. **[README](../README.md) "발급 → 검증 흐름" mermaid** → IdP(issuer) ↔ Resource Server(consumer) 관계
3. **[docs/adr/](adr/)** → 왜 그렇게 했나 (ADR 18개) ← 이 레포의 핵심 학습 자료. 특히 0003(JWK rotation) → 0004 / 0015(refresh reuse + grace) → 0016(OPA ABAC) → 0017 / 0018(RFC 7662 / 7009)
4. **위 패턴 표** 에서 관심 패턴 → 코드 + 해당 ADR + dev-lab 이론
5. **[docs/security/owasp-mapping.md](security/owasp-mapping.md)** → OWASP 관점 점검 항목

> 이론 보강은 [dev-lab](https://github.com/ssa1004/dev-lab) 에서. 추천 진입점:
> [`api-design`](https://github.com/ssa1004/dev-lab) (OAuth2 / OIDC / JWT / RFC 표준 / 인증 vs 인가) →
> [`vault`](https://github.com/ssa1004/dev-lab) (key / secret rotation, JWK / KMS) →
> [`redis`](https://github.com/ssa1004/dev-lab) (토큰 / 세션 / rate-limit 저장) →
> [`system-design`](https://github.com/ssa1004/dev-lab) (헥사고날) →
> [`resilience`](https://github.com/ssa1004/dev-lab) · [`observability`](https://github.com/ssa1004/dev-lab).
