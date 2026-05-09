# ADR-0002: JWT 서명 알고리즘 — RS256 (vs EdDSA / ES256)

## 상태
적용

## 배경
JWT 서명 알고리즘 선택지는 크게 셋:

- **HS256** (HMAC) — 대칭키. issuer 와 verifier 가 같은 비밀을 공유해야 하므로 *외부
  consumer 가 검증하는* 우리 IdP 시나리오에는 부적합.
- **RS256** (RSA-SHA256) — 비대칭. 표준이 가장 널리 깔려 있고, 모든 OAuth2 클라이언트가
  지원.
- **EdDSA / ES256** (Ed25519, ECDSA-P256) — 비대칭. 키 / 서명이 짧고 빠름. 일부 오래된
  클라이언트 호환성이 떨어짐.

## 결정
**RS256 / RSA 2048bit**.

이유:
1. 외부 consumer (다른 internal service, 모바일 앱 SDK, 향후 외부 파트너) 가 어떤 JWT
   라이브러리를 쓸지 모르므로 *가장 호환성이 넓은* RS256 을 기본값으로.
2. RSA 2048 은 NIST 권고 (2030 까지 안전) 를 충족.
3. JWK header 의 `alg` 가 명시적이어서 verifier 가 알고리즘 혼동 공격 ({alg: none},
   {alg: HS256 with RSA pubkey}) 을 차단하기 쉬움.

## 다시 검토할 시점
- 모바일 SDK 에서 키 / 서명 크기가 문제가 될 때 (배터리 / 대역폭). 그때 EdDSA 추가 (`alg`
  복수 노출 + JWK rotation 으로 점진 전환).
- HSM / KMS 가 EdDSA 를 더 잘 지원하게 될 때.

## 결과
- JWKS endpoint 의 키 1개당 ~360 bytes (PEM 직렬화 기준).
- 서명 시간 ~1ms (M1, JIT 워밍업 후) — access token 발급 hot path 에 부담 없음.
- (단점) 향후 EdDSA 로 전환할 때 클라이언트 라이브러리 호환성 매트릭스를 따로 관리해야 함.
