# Contributing

본 저장소의 개발 흐름과 commit 규칙을 정리한 문서입니다.

## 브랜치 전략

GitHub Flow 를 따릅니다. `main` 은 항상 배포 가능한 상태로 유지되며, 모든 작업은 feature
브랜치에서 진행됩니다.

```
main (protected)
  ├── feature/refresh-reuse-detection      ← 기능 브랜치
  ├── fix/jwk-rotation-grace-period
  └── docs/adr-rbac-vs-abac
```

흐름은 `git checkout -b feature/<짧은-설명>` → 작업 → PR → 코드 리뷰 + CI 통과 → Squash and
merge 입니다. 머지 후 feature 브랜치는 즉시 삭제합니다.

## Commit 메시지

Conventional Commits 형식을 따릅니다.

```
<type>(<scope>): <짧은 설명, 50자 이내>

<상세 설명, 한 줄에 72자 이내>
- 무엇이 / 왜 변경되었는지
- 영향받는 모듈
```

사용하는 type: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`.
scope 에는 모듈명 (`domain`, `application`, `adapter-out`, `bootstrap` 등) 이 들어갑니다.

JWK / refresh / MFA / RBAC 가 도메인의 핵심이므로 관련 commit 이 자주 발생합니다.

### 예시

```
feat(application): refresh token rotation + reuse detection

- RefreshTokenService 가 회전 시 hash 를 Redis 에 grace 5초로 보존
- 같은 hash 가 다시 들어오면 SecurityIncidentDetector 호출
- 사용자의 모든 refresh 강제 revoke + audit log
```

```
fix(adapter-in): /oauth2/jwks 가 직전 키를 누락하던 회귀

JwkRotationService 가 두 키 (current + previous) 를 JWKSet 에 같이 노출해야
grace period 동안 두 토큰 모두 검증 통과합니다. 회전 시 previous 를 빠뜨려서
회전 직후 발급된 토큰이 401 받던 문제를 수정합니다.
```

## Commit 단위

한 commit 은 한 가지 논리적 변경을 담는 것을 원칙으로 합니다. 새 기능 + 리팩터링 + 버그
수정이 한 commit 에 같이 포함되어 있다면 거의 항상 분리 가능합니다. WIP commit 은 PR 머지
전에 squash 합니다.

## 테스트

PR 전 `./gradlew check` 통과가 필수입니다. 빠른 단위 테스트만 별도로 실행하려면 다음 명령을
사용합니다.

- 도메인: `:auth-domain:test`
- 유스케이스: `:auth-application:test`
- adapter-out 통합 (Postgres + Redis Testcontainer): `:auth-adapter-out:test`
- e2e (전체 부팅 + REST + Authorization Server): `:e2e-tests:test`

## 코드 스타일

- Java: Google Java Format 또는 IntelliJ default
- 주석 / 문서는 자연스러운 한국어 (영어 직역체 지양)

## 보안 작업 시 추가 규칙

- 비밀번호 / TOTP secret / token 을 평문으로 로그에 찍지 않습니다.
- JWK / 비대칭 키 자료는 `.gitignore` 의 `*.pem`, `local-jwk.json` 등에 의해 항상 무시됩니다.
- DB 마이그레이션 (`V*__*.sql`) 으로 컬럼을 추가할 때 평문 비밀 컬럼은 받지 않습니다.
