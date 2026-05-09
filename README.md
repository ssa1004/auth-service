# auth-service

OAuth2 / OIDC IdP. 다른 internal service 들이 *consumer* (JWT 검증) 인 반면
이 서비스는 *issuer*. JWT 발행 + JWK rotation + refresh token rotation + RBAC
+ multi-tenant + 2FA + audit 를 한 묶음으로 제공합니다.

## 모듈

| 모듈 | 역할 |
| --- | --- |
| `auth-domain` | User / Tenant / Role / Permission / RefreshToken / MfaSecret 도메인 모델 (Spring 무관) |
| `auth-application` | 유스케이스 + Port 인터페이스 |
| `auth-adapter-out` | JPA / Redis / 메일 / TOTP 구현체 |
| `auth-adapter-in` | REST + Spring Authorization Server endpoint |
| `auth-bootstrap` | Spring Boot main + JWK rotation + Flyway |
| `e2e-tests` | Postgres + Redis Testcontainer 통합 시나리오 |

## 핵심 유스케이스

- `RegisterUserUseCase` — 이메일 + 비밀번호 + 테넌트 회원가입 (BCrypt cost=12)
- `LoginUseCase` — 비밀번호 검증 → MFA 분기 또는 access + refresh 발급
- `VerifyMfaUseCase` — TOTP 코드 검증 → 인증 완료
- `RefreshTokenUseCase` — refresh token 회전 + 재사용 탐지 → 모든 세션 강제 revoke
- `RevokeSessionUseCase` — 사용자가 *내 세션* 에서 특정 세션 revoke
- `ListMySessionsUseCase` — 활성 refresh 목록 (디바이스 / IP / 마지막 사용 시각)
- `AssignRoleUseCase` — 운영자가 사용자에게 role 부여
- `AuditLoginAttemptsUseCase` — 로그인 성공 / 실패 audit log

## 빌드 / 실행

```bash
./gradlew check
./gradlew :auth-bootstrap:bootRun
```

세부 구성, ADR, 인프라 구성은 추후 다듬어 추가합니다.
