# ADR-0001: 헥사고날 + Spring Authorization Server 도입

## 상태
적용

## 배경
auth-service 는 다른 internal service 들이 *consumer* (JWT 검증) 인 상황에서 *issuer*
역할을 합니다. JWT 발행 / JWK rotation / refresh token rotation / RBAC / multi-tenant
/ 2FA / audit 까지 한 번에 책임지므로 *외부 라이브러리 (Spring Authorization Server,
Nimbus JOSE, BCrypt 등) 의 침입* 이 가장 빈번한 모듈입니다.

도메인 (User / Tenant / Role / RefreshToken / MfaSecret) 은 이런 라이브러리의 어노테이션
/ 클래스 / 직렬화 규약에 끌려가서는 안 됩니다 — 라이브러리 교체 (예: Spring AS → 자체
JWS 발행기) 가 도메인 코드 수정으로 번지면 OAuth2 / OIDC 표준이 변할 때마다 회귀가
생깁니다.

## 결정
헥사고날 (Ports and Adapters) 4개 모듈 + 부팅 모듈 + e2e:

- `auth-domain` — 순수 Java + jakarta.validation. Spring / JPA / Nimbus 의존성 0.
- `auth-application` — 유스케이스 + Port (in/out). Spring `@Service`, `@Transactional`,
  `spring-security-crypto` (PasswordEncoder interface) 까지만.
- `auth-adapter-out` — JPA / Redis / TOTP / BCrypt / AES / Nimbus JOSE 등 *모든 외부
  의존성* 의 구현체.
- `auth-adapter-in` — REST controller + Spring Authorization Server endpoint.
- `auth-bootstrap` — Spring Boot main + JWK rotation 스케줄러 + `SecurityFilterChain`
  조립.

OAuth2 표준 endpoint (`/oauth2/token`, `/oauth2/jwks`,
`/.well-known/openid-configuration`) 는 Spring Authorization Server 1.4 가 자동 노출.
우리가 자체로 노출하는 first-party endpoint (`/api/v1/auth/login` 등) 는 Spring AS 와
별도 chain 으로 운영합니다 (ADR-0006).

## 결과
- 도메인 단위 테스트는 Spring 컨텍스트 없이 ms 단위로 끝남 (auth-domain: 26 test, < 1s).
- 라이브러리 교체가 adapter-out 안에서 끝남 (예: BCrypt → Argon2 는 한 클래스 교체).
- (단점) 한 패키지 안에서 끝낼 수 있는 변경도 4개 모듈을 오가는 경우가 생김 — 작은 변경의
  PR 노이즈가 큰 monolith 보다 늘어남.
- (단점) Spring AS 의 표준 동작과 우리 자체 흐름이 같은 앱 안에 공존 — `SecurityFilterChain`
  order 가 헷갈리기 쉬움 (ADR-0006 에서 명시적으로 분리).
