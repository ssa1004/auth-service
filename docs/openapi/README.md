# OpenAPI spec

`auth-service` 의 REST API 를 OpenAPI 3 spec 으로 build-time export 한다.

## 무엇이 들어가나

- `auth-service.yaml` — 빌드 시 생성되는 OpenAPI 3 문서. 외부 참조 / SDK codegen 의 단일 진실값.
  - REST controller (`/api/v1/auth`, `/api/v1/me/sessions`, `/api/v1/admin`)
  - RFC 7662 introspection (`/oauth2/introspect`), RFC 7009 revocation (`/oauth2/revoke`)
  - Spring Authorization Server 가 노출하는 OAuth2 / OIDC endpoint
    (`/oauth2/token`, `/oauth2/jwks`, `/.well-known/openid-configuration`)

> 이 디렉토리의 `auth-service.yaml` 은 코드(controller / `OpenApiConfig`)에서 생성된 산출물이다.
> 로컬에서 수기로 편집하지 않는다 — 손으로 고친 spec 은 코드와 어긋난다.
>
> **현재 상태**: `auth-service.yaml` 가 레포에 commit 되어 있다. CI 의 drift 게이트
> (`.github/workflows/ci.yml` 의 `openapi-spec` job)가 매 push/PR 마다 아래 "생성 방법" 으로
> spec 을 재생성하고 `git diff --exit-code` 로 commit 된 파일과 비교한다 — 코드가 바뀌었는데
> spec 을 갱신하지 않으면 CI 가 실패한다.

## 생성 방법

외부 인프라 ZERO 의 `dev` 프로파일로 앱을 부팅한 뒤 (`application-dev.yml` — H2 in-memory,
in-memory rate limiter, Redis/SMTP health 비활성), springdoc 이 노출한 `/v3/api-docs` (JSON)
를 받아 `yq` 로 YAML 로 변환해 `docs/openapi/auth-service.yaml` 로 저장한다. Postgres / Redis
/ Docker 가 필요 없다.

```bash
./scripts/gen-openapi.sh
```

스크립트가 하는 일:

```bash
# 1. dev 프로파일로 부팅 (free port)
./gradlew :auth-bootstrap:bootRun --args='--spring.profiles.active=dev --server.port=18080'
# 2. /actuator/health 가 UP 이 될 때까지 polling
# 3. springdoc JSON 을 받아 YAML 로 변환
curl -fsS http://localhost:18080/v3/api-docs | yq -P -o=yaml '.' > docs/openapi/auth-service.yaml
# 4. 앱 종료
```

> 참고: springdoc 의 native YAML endpoint(`/v3/api-docs.yaml`)는 `SecurityConfig` 의 public
> matcher(`/v3/api-docs/**`)가 `.yaml` 형제 경로를 안 덮어 403 이다. 그래서 permit 된 JSON
> endpoint(`/v3/api-docs`)를 받아 `yq` 로 변환한다 — e2e `OpenApiSpecE2eTest` 도 같은 JSON
> endpoint 를 검증한다. (build-time export 용 `org.springdoc.openapi-gradle-plugin` 의
> `generateOpenApiDocs` 태스크는 `.yaml` 을 fetch 하므로 같은 이유로 현재는 쓰지 않는다.)

CI 에서는 동일 스크립트를 `dev` 프로파일로 실행해 spec 을 재생성하고 commit 된 파일과
비교한다(drift 게이트). service container 가 필요 없다.

## 보는 법

- Swagger UI — 앱 실행 후 `http://localhost:8080/swagger-ui.html`
- Redoc — `npx @redocly/cli preview-docs docs/openapi/auth-service.yaml`
- 통합 뷰어 — profile repo `ssa1004/ssa1004` 의 `docs/api/index.html` (9 service spec 드롭다운)
