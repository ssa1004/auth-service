# ADR-0018: Token Revocation (RFC 7009) — admin 강제 revoke 표준 endpoint

## 상태
적용

## 배경

본 IdP 의 사용자는 자기 세션의 refresh token 을 *내 세션 목록* 에서 직접 revoke
할 수 있다 ({@code RevokeSessionUseCase}). 일반 사용자 셀프 서비스로 충분한 경우는 이
경로로 처리된다.

운영자가 즉시 차단해야 하는 시나리오는 다른 흐름이 필요하다.

- **계정 정지** — 결제 사기 / ToS 위반 등으로 사용자를 차단할 때, 사용자가 가진 모든 access
  / refresh token 을 동시에 종료해야 함.
- **탈취 대응** — 보안 콘솔에서 의심 계정의 토큰을 강제 revoke. 사용자가 직접 로그아웃하기
  를 기다릴 수 없음.
- **외부 도구 / SDK 통합** — RFC 7009 는 OAuth2 표준 endpoint. 외부 SDK / 보안 콘솔이
  본 IdP 에 통합될 때 표준 path 를 기대한다.

해결책은 두 가지를 함께 제공:
1. RFC 7009 의 표준 `POST /oauth2/revoke` endpoint
2. ADR-0017 의 introspect 가 즉시 inactive 응답을 보내도록 연동 (Redis 블록리스트 + DB 마킹)

## 결정

### `POST /oauth2/revoke` — RFC 7009 응답

application/x-www-form-urlencoded 본문으로 `token` 과 선택적 `token_type_hint` 를 받는다.

```http
POST /oauth2/revoke HTTP/1.1
Authorization: Basic <admin_client_id:admin_client_secret>
Content-Type: application/x-www-form-urlencoded

token=<access_or_refresh>&token_type_hint=refresh_token
```

응답은 본문 없는 200 OK — RFC 7009 §2.2.

### 알 수 없는 / 만료된 / 다른 client 의 token 도 200

RFC 7009 §2.2 의 핵심은 *정보 누설 차단* 이다. 호출 client 가 자기 권한 안에서 임의 token
을 보내면 "유효한 token 이었나, 가짜였나" 가 응답으로 드러나면 안 된다. 인증된 client
가 보낸 모든 정상 형식 요청은 200.

예외 — 호출 client 자체가 admin 권한 (token.revoke scope) 을 가지지 않으면 RFC 7009
§2.2.1 의 `unauthorized_client` 와 같은 의미로 403 으로 거절. *권한 자체가 없는 호출은
명확히 차단* 이 RFC 7009 가 허용하는 범위.

### Admin scope — `token.revoke`

자체 사용자의 셀프 revoke 와 운영자 강제 revoke 가 같은 endpoint 에 섞이는 것은 위험하다
(권한 모델 혼란). RFC 7009 endpoint 는 *반드시* admin scope 보유 client 만 호출. Spring
Authorization Server 의 `RegisteredClient` 에 별도 admin client (`internal-admin`) 를
등록하고 `token.revoke` scope 만 부여한다.

OPA 정책 `policies/token_revocation.rego` 가 결정 단일 진입점:

```rego
package auth.token.revoke

import rego.v1

default allow := false

allow if {
    "token.revoke" in input.subject.scopes
}

reasons contains "missing_token_revoke_scope" if {
    not allow
    not "token.revoke" in input.subject.scopes
}
```

코드는 `policyDecisionService.evaluate("auth/token/revoke", request)` 한 번만 호출 —
정책 변경은 Rego 만 수정하면 끝 (ADR-0016 의 PDP 패턴). 새 admin client 가 추가되어도
코드 재배포 필요 없음.

### Access JWT revoke — Redis 블록리스트 (ADR-0017 연동)

RFC 7009 자체는 access token 차단 방법을 강제하지 않는다. self-contained JWT 의 한계로
서명만으로는 즉시 차단 불가능 — 별도 블록리스트가 필요하다.

revoke endpoint 가 access JWT 를 받으면:
1. JWT 디코드 → jti / exp 추출
2. `at:revoked:<jti>` 키로 Redis 에 적재. TTL = 잔여 유효시간 (max 15분 — access TTL).
3. introspect 호출 (ADR-0017) 이 같은 블록리스트를 확인 → `active=false`.

자동 정리 — TTL 만료 후 Redis 가 알아서 제거. 별도 정리 잡 불필요.

### Refresh token revoke — DB 마킹

refresh token 은 hash 로 lookup → `REVOKED_BY_ADMIN` 으로 마킹. 새로운 status 값을
도메인에 추가해 *어떤 경로로 revoke 됐는지* 가 audit / 분석에서 분명하게 보인다 (사용자
직접 / 운영자 강제 / reuse detection / 회전 종료).

### 사용자 세션의 *모든* 토큰 한 번에 revoke 는 후속

본 ADR 는 *제출된 토큰 하나* 만 revoke 한다 (RFC 7009 의 표준 시맨틱). "사용자의 모든
토큰을 한 번에 종료" 는 별도 admin endpoint 가 더 적합 (RFC 외 확장). 사용자 정지 흐름은
계정 상태를 LOCKED 로 바꾸는 별도 use case 가 책임지고, 본 endpoint 는 표준 호환만 본다.

### audit — `TOKEN_REVOKED_BY_ADMIN`

호출자 client / 결과 (access / refresh / unknown) / jti 또는 sessionId / blocklist TTL
까지 한 줄. 사후 *누가 무엇을 revoke 했는가* 추적 가능. 토큰 평문 / 사용자 비밀번호는
절대 적재하지 않는다 (ISMS-P).

## 대안

### 사용자 정지 시 모든 토큰 자동 revoke 만 하고 RFC endpoint 안 만듦
탈락. 외부 SDK / 보안 콘솔이 RFC 7009 표준 path 를 기대. 자체 endpoint 만 두면 통합 비용이
늘어남. 그리고 사용자 정지가 아닌 *특정 토큰만* revoke 하는 시나리오 (예: 의심 IP 의 한
세션만 차단) 에 자체 endpoint 가 따로 필요해짐.

### 모든 client 가 token.revoke 호출 가능 — scope 검증 없음
탈락. 일반 service client 가 다른 사용자의 토큰을 임의로 revoke 할 수 있게 되어 *서비스
거부 도구* 가 된다. 권한 분리는 절대.

### Spring Authorization Server 의 기본 revocation 그대로 사용
탈락. SAS 의 `OAuth2TokenRevocationAuthenticationProvider` 는 SAS 가 발행한 OAuth2
authorization (자체 token store) 만 처리. 본 IdP 의 access JWT 와 refresh aggregate 는
SAS token store 를 거치지 않으므로 SAS 의 기본 revocation 은 *우리 토큰을 revoke 하지
못한다* — 결국 자체 controller 가 정합.

### Refresh 만 revoke, access 는 만료까지 유효 허용
탈락. access TTL (15분) 안에 공격자가 자유롭게 사용 가능 — 사용자 정지 시나리오의 SLA
요구 (10초 이내 차단) 와 충돌. 블록리스트 추가 비용 (Redis 한 번 SET) 보다 보안 위험이
훨씬 큼.

## 결과

- 외부 SDK / 보안 콘솔이 RFC 표준 path 로 본 IdP 와 통합 가능.
- 운영자 강제 revoke 가 introspect (ADR-0017) 와 함께 *최대 10초* 안에 모든 노드 / 모든
  Resource Server 에 반영됨 (introspect cache TTL 기준).
- 권한 모델은 OPA 정책 한 줄 — 새 admin client 추가 / 권한 변경이 코드 재배포 없이
  반영됨.
- audit_entries 에 모든 admin revoke 가 한 줄씩 — *누가 누구의 토큰을 언제 종료했는가* 가
  영구 기록.
- (단점) Redis 블록리스트가 새 외부 의존성. Redis down 시 access JWT 의 즉시 revoke 효과가
  사라짐 — 후속에서 fail-closed 모드 검토.
- (단점) RFC 7009 의 200 응답 규칙이 *권한 모델의 누락* 을 가린다. 잘못 설정된 admin
  client 가 잘못된 token 을 보내도 200 — audit log 와 사후 분석이 핵심.
- (단점) admin client_secret 이 운영에서 평문으로 보관되면 권한 우회 위험.
  [CONTRIBUTING.md](../../CONTRIBUTING.md) 의 보안 규칙 (KMS / Vault / k8s Secret 외부
  주입) 을 운영 전환 시 반드시 적용.

## 후속

- `POST /api/v1/admin/users/{id}/sessions` — *사용자의 모든 토큰을 한 번에 revoke* 하는
  자체 endpoint (사용자 정지 흐름). RFC 7009 와 별도.
- Redis 블록리스트의 fail-closed 모드 — Redis down 시 introspect 가 401 만 반환할지 정책
  옵션.
- mTLS 기반 admin client 인증 — client_secret 보다 안전한 회사 내부 표준.
- admin revoke 알람 — 5분 안에 같은 admin client 가 N 회 이상 revoke 호출하면 SIEM
  알람 (계정 탈취 또는 admin 권한 오용 신호).
