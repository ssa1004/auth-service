# ADR-0001: 헥사고날 + Spring Authorization Server 도입

## 상태
적용

## 배경
auth-service 는 다른 internal service 들이 JWT 를 검증하는 consumer 일 때 JWT 를 발행하는
issuer 역할을 합니다. JWT 발행, JWK rotation, refresh token rotation, RBAC, multi-tenant,
2FA, audit 까지 한 번에 책임지므로 외부 라이브러리 (Spring Authorization Server, Nimbus
JOSE, BCrypt 등) 가 코드 곳곳에 들어오기 가장 쉬운 모듈입니다.

도메인 (User / Tenant / Role / RefreshToken / MfaSecret) 은 이런 라이브러리의 어노테이션
/ 클래스 / 직렬화 규약에 끌려가서는 안 됩니다. 라이브러리 교체 (예: Spring AS 에서 자체
JWS 발행기로) 가 도메인 코드 수정으로 번지면 OAuth2 / OIDC 표준이 변할 때마다 회귀가
생깁니다.

## 결정
헥사고날 (Ports and Adapters) 4개 모듈 + 부팅 모듈 + e2e:

- `auth-domain` — 순수 Kotlin + jakarta.validation. Spring / JPA / Nimbus 의존성 0.
- `auth-application` — 유스케이스 + Port (in/out). Spring `@Service`, `@Transactional`,
  `spring-security-crypto` (PasswordEncoder interface) 까지만.
- `auth-adapter-out` — JPA / Redis / TOTP / BCrypt / AES / Nimbus JOSE 같은 모든 외부
  의존성의 구현체.
- `auth-adapter-in` — REST controller + Spring Authorization Server endpoint.
- `auth-bootstrap` — Spring Boot main + JWK rotation 스케줄러 + `SecurityFilterChain`
  조립.

OAuth2 표준 endpoint (`/oauth2/token`, `/oauth2/jwks`,
`/.well-known/openid-configuration`) 는 Spring Authorization Server 1.4 가 자동 노출.
우리가 자체로 노출하는 first-party endpoint (`/api/v1/auth/login` 등) 는 Spring AS 와
별도 chain 으로 운영합니다 (ADR-0006).

## 결과
- 도메인 단위 테스트는 Spring 컨텍스트 없이 ms 단위로 끝납니다 (auth-domain: 26 test, < 1s).
- 라이브러리 교체가 adapter-out 안에서 끝납니다 (예: BCrypt → Argon2 는 한 클래스 교체).
- (단점) 한 패키지 안에서 끝낼 수 있는 변경도 4개 모듈을 오가는 경우가 생깁니다. 작은
  변경의 PR diff 가 monolith 보다 늘어납니다.
- (단점) Spring AS 의 표준 동작과 자체 first-party 흐름이 같은 앱 안에 공존하므로
  `SecurityFilterChain` order 가 헷갈리기 쉽습니다 (ADR-0006 에서 명시적으로 분리).

## 용어 풀이 (쉽게)

- **헥사고날 아키텍처 (port/adapter)** — 핵심 업무 로직을 가운데 두고 DB·Redis·웹·라이브러리는 콘센트(port)와 플러그(adapter)로만 연결하는 구조. 라이브러리를 바꿔도 플러그만 갈아끼우면 돼서 핵심 코드는 안 건드린다.
- **issuer vs consumer (IdP)** — issuer는 신분증(JWT)을 직접 '발급'하는 기관, consumer는 받은 신분증이 진짜인지 '검증'만 하는 쪽. auth-service는 포트폴리오에서 유일하게 토큰을 찍어내는 발급처다.
- **JWS / 자체 JWS 발행기** — JWT에 위변조 방지용 서명을 박는 표준(JSON Web Signature). Spring 라이브러리가 해주던 서명을 직접 구현으로 바꾸는 것이 '자체 JWS 발행기'.
- **SecurityFilterChain (필터 체인)** — 들어온 요청을 인증·인가 규칙으로 차례차례 검사하는 Spring Security의 검문소 줄. 표준 endpoint용과 자체 endpoint용을 별도 줄로 나눠 순서가 안 꼬이게 한다.
