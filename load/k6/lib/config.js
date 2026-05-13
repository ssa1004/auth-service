// k6 시나리오 공용 설정.
//
// 환경 변수 (실행 시 override):
//   BASE_URL              auth-service base — default http://localhost:8080
//   JWKS_URL              JWK Set endpoint — default $BASE_URL/oauth2/jwks
//                         (Spring Authorization Server 1.4 가 노출하는 표준 경로)
//   CLIENT_ID             client_credentials grant 의 client_id
//   CLIENT_SECRET         client_credentials grant 의 client_secret
//                         (운영 secret 절대 commit / 로그 금지)
//   TENANT_SLUG           /auth/login 시 tenant 식별자
//   USER_EMAIL            /auth/login 시 사용자 (사전 register 필요)
//   USER_PASSWORD         /auth/login 시 비밀번호
//
// 운영 / 스테이지에서는 모두 환경 변수로 주입. 기본값은 docker-compose 로컬 시드.
export const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

// /.well-known/jwks.json 은 일반적인 OAuth2 관례이고, Spring Authorization Server 1.4 의
// 실제 endpoint 는 /oauth2/jwks. 둘 다 가능하도록 환경 변수로 override.
export const JWKS_URL = __ENV.JWKS_URL || `${BASE_URL}/oauth2/jwks`;

// client_credentials grant (internal-service / internal-service-secret-change-me 는
// AuthorizationServerClientsConfig 의 로컬 시드. 운영에서는 별도 client 주입.)
export const CLIENT_ID = __ENV.CLIENT_ID || 'internal-service';
export const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'internal-service-secret-change-me';
export const SCOPE = __ENV.SCOPE || 'api.read';

// /api/v1/auth/login + /refresh 시나리오용 fixture. e2e-tests 의 시드 사용자 / tenant.
export const TENANT_SLUG = __ENV.TENANT_SLUG || 'acme';
export const USER_EMAIL = __ENV.USER_EMAIL || 'alice@example.com';
export const USER_PASSWORD = __ENV.USER_PASSWORD || 'longenoughpw1234';

// 공통 헤더 — 회귀 추적용 tag 로 같이 묶기 좋게 함수로 추출.
export function jsonHeaders() {
  return { 'Content-Type': 'application/json' };
}

export function formHeaders() {
  return { 'Content-Type': 'application/x-www-form-urlencoded' };
}
