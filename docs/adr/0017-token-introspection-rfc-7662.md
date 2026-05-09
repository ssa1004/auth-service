# ADR-0017: Token Introspection (RFC 7662) — JWT self-validate vs introspection

## 상태
적용

## 배경

본 IdP 는 RS256 self-contained JWT 를 access token 으로 발급한다 (ADR-0001 / 0002).
Resource Server (consumer) 는 JWKS 를 한 번 받아 두면 *혼자서* 서명 / 만료 / 발급자를
검증할 수 있어 IdP 에 매 요청마다 묻지 않아도 된다. p99 latency 가 짧고 IdP 가 다운돼도
검증이 가능하다는 게 self-validate 의 강점이다.

문제는 *발행 후 강제 종료* 시나리오다.

- 사용자 정지 / 계정 탈취 의심 — 운영자가 사용자의 모든 토큰을 즉시 차단해야 하는 경우.
- 권한 회수 — 어떤 사용자에게서 권한이 박탈됐는데, 그가 가진 access token 의 TTL 이 아직
  10분 남아 있다면 그 10분 동안 그대로 사용 가능.
- 탈취 대응 — refresh token 은 reuse detection 으로 즉시 차단되지만, 이미 발급된 access
  token 은 self-validate 만으로는 막을 방법이 없다.

해결책은 Resource Server 가 self-validate 대신 (또는 함께) IdP 에 직접 *지금 이 토큰이
유효한가* 를 묻는 것이다 — RFC 7662 의 Token Introspection 이 표준 형식이다.

## 결정

### `POST /oauth2/introspect` — RFC 7662 응답

application/x-www-form-urlencoded 본문으로 `token` 과 선택적 `token_type_hint` 를 받고,
JSON 응답을 RFC 7662 §2.2 형식으로 반환한다.

```http
POST /oauth2/introspect HTTP/1.1
Authorization: Basic <client_id:client_secret>
Content-Type: application/x-www-form-urlencoded

token=eyJhbGciOiJSUzI1NiIs...&token_type_hint=access_token
```

```json
{
  "active": true,
  "scope": "api:read api:write",
  "client_id": "internal-service",
  "token_type": "Bearer",
  "exp": 1762640400,
  "iat": 1762639500,
  "sub": "8b9e...e7c1",
  "tnt": "f0f1...c2c8",
  "roles": ["platform_admin"],
  "iss": "https://auth.example.com",
  "jti": "8d3a..."
}
```

알 수 없는 토큰 / 만료 / revoke 된 토큰 / 외부 issuer 의 가짜 토큰 모두 RFC 7662 §2.2
권고에 따라 `{"active":false}` 만 반환한다 — 정보 누설을 막기 위해 다른 필드는 모두 생략.

### `client_secret_basic` 으로 인증된 client 만 호출 가능

introspect endpoint 를 외부에 익명으로 노출하면 *토큰 oracle* 이 된다 — 공격자가 훔친
토큰을 자유롭게 검증할 수 있게 된다. SecurityFilterChain 에서 HTTP Basic 으로 등록된
client 만 통과시키며, Spring Authorization Server 에 등록된 `internal-service` 같은
client_credentials grant client 가 호출하는 것을 표준 흐름으로 본다.

### Revoke 즉시 반영 — 두 출처

1. **Refresh token** — 본 IdP 의 `refresh_tokens` 테이블에서 hash 로 조회. 상태가 ACTIVE
   가 아니거나 만료됐으면 `active=false`.
2. **Access JWT** — Redis 의 `at:revoked:<jti>` 블록리스트를 확인. 운영자가 RFC 7009
   revoke (ADR-0018) 로 jti 를 등록하면 introspect 호출이 즉시 `active=false` 응답으로
   바뀐다. TTL 은 토큰의 남은 유효시간으로 잡아 자동 정리.

이 둘이 합쳐져 *발행 후 강제 종료* 시나리오가 마침내 모든 인스턴스에 즉시 반영된다.

### Resource Server 측 cache 권장 — 10초 TTL

introspect 는 매 요청마다 IdP 에 왕복 호출이라 무캐시면 latency / IdP 부하가 커진다.
Resource Server 가 `(token_hash, exp)` 키로 10초 in-memory cache 하는 것을 표준으로
권장한다.

- 10초 — 운영자가 revoke 한 토큰이 *최대 10초 안에* 모든 노드에서 차단된다는 SLA.
  사용자 정지 시나리오에서 10초 지연은 허용 범위.
- 키에 `token_hash` 사용 — 평문 token 을 cache 키로 두지 않음 (메모리 dump 위험 차단).
- `exp` 가 cache 만료 시각보다 더 먼저면 그 시점까지만 cache.

긴 TTL (30s+) 은 revoke 반영이 늦어 SLA 가 무너진다. 짧은 TTL (1s) 은 cache 효과가 거의
없어 IdP 부담이 introspect 비활성화와 비슷해진다.

### audit — `TOKEN_INTROSPECTED` 한 줄

매 introspect 호출에 audit 한 줄 (`active`, 호출한 client_id, token_type_hint, sub /
tenant). 토큰 자체는 적재 X. 평소 트래픽이 일정하다가 갑자기 특정 사용자에 대한 introspect
폭증이 보이면 *공격자가 토큰 oracle 로 brute-force* 하는 신호로 간주할 수 있다.

## 대안

### 항상 self-validate 만, introspect 안 함
탈락. 강제 revoke 가 access TTL 동안 반영 안 되어 운영 사고 (사용자 정지 / 권한 박탈) 시
대응이 늦다. *15분 후에야 차단* 은 보안 사건 대응 SLA 로 치명적.

### Access TTL 을 1분 수준으로 단축
검토했지만 탈락. refresh 회전 호출이 그만큼 늘어나 IdP / Redis 부하 가중. mobile / SPA 의
리소스 호출 대부분이 매번 refresh 거쳐야 함 — 사용자 경험과 latency 가 무너짐.

### Spring Authorization Server 의 기본 introspection 그대로 사용
탈락. SAS 의 introspect 는 *SAS 가 발행한 OAuth2Authorization 객체* 만 처리한다. 본 IdP
의 access JWT 는 Nimbus 로 직접 서명한 self-contained 토큰이고, refresh 는 자체
`refresh_tokens` aggregate 라 SAS token store 를 거치지 않는다 → 호출하면 항상
`active=false`. 우리 도메인을 알도록 자체 controller 를 두는 게 정합.

## 결과

- Resource Server 가 RFC 표준 형식으로 토큰 유효성을 즉시 확인 가능 — 사용자 정지 / 권한
  회수 시나리오의 차단 SLA 가 *최대 10초* (cache TTL) 로 정량화됨.
- 외부 SDK / 표준 OAuth2 클라이언트가 별도 통합 작업 없이 본 IdP 와 호환.
- audit_entries 에 introspect 호출이 한 줄씩 남아 *토큰 oracle 공격* 패턴을 SIEM 에서
  검출 가능.
- (단점) introspect 호출이 추가 latency (RTT + Redis 조회) 를 만든다. 핵심은 Resource
  Server 측 cache — 캐시 적중 시 RTT 0. 캐시 미적용 환경은 RPS 가 높을수록 IdP 부하 증가.
- (단점) Access JWT 의 강제 차단을 위해 Redis 블록리스트가 필요해 *외부 의존성 추가*.
  Redis down 시 introspect 가 fail-closed 로 가정하지 않으면 (현재 구현은 fail-open 단순
  처리) revoke 우회 가능. 후속에서 fail-closed / 로컬 cache 패턴 검토.
- (단점) Resource Server 가 introspect 호출을 안 하고 self-validate 에만 의존하면 본 ADR
  의 효과가 0. 운영 가이드 (README) 에 명확히.

## 후속

- Resource Server 측 표준 cache wrapper (`InternalIntrospectClient`) — 10초 TTL,
  metric 노출. 본 ADR 범위 밖.
- Redis 블록리스트의 fail-closed 모드 — Redis 장애 시 introspect 를 일시 중지하고
  401 만 반환할지 정책 옵션 추가.
- introspect 의 mTLS 인증 — 회사 내부망 서비스 간에는 client_secret 보다 mTLS 가 표준.
- `userinfo` claim 와의 통합 — RFC 7662 응답에 본인 부분 정보를 일부 노출하는 패턴.
