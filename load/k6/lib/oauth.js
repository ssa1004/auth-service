// OAuth2 / first-party 인증 호출 helper.
//
// k6 시나리오에서 반복적으로 쓰는 호출 (client_credentials token 발급, /auth/login,
// /auth/refresh, /oauth2/introspect) 을 한 곳에 모아 시나리오 본문은 *측정 의도* 만 남게
// 합니다.
//
// 모든 함수는 k6 의 http.Response 를 그대로 반환합니다 — check / threshold 는 호출하는
// 시나리오에서 부착하도록 위임합니다.
import http from 'k6/http';
import encoding from 'k6/encoding';
import {
  BASE_URL,
  CLIENT_ID,
  CLIENT_SECRET,
  SCOPE,
  formHeaders,
  jsonHeaders,
} from './config.js';

/**
 * RFC 6749 §4.4 client_credentials grant 로 access token 발급.
 *
 * - Authorization: Basic <base64(clientId:clientSecret)>
 * - body: grant_type=client_credentials&scope=...
 *
 * 호출자는 res.status / res.json('access_token') 으로 결과 사용.
 */
export function issueClientCredentialsToken(tag = 'token_issue') {
  const basic = encoding.b64encode(`${CLIENT_ID}:${CLIENT_SECRET}`);
  const body = `grant_type=client_credentials&scope=${encodeURIComponent(SCOPE)}`;
  return http.post(`${BASE_URL}/oauth2/token`, body, {
    headers: {
      ...formHeaders(),
      Authorization: `Basic ${basic}`,
    },
    tags: { name: tag },
  });
}

/**
 * RFC 7662 introspection — Resource Server 가 token 의 active 여부를 IdP 에 묻는 표준 endpoint.
 *
 * 본 endpoint 는 client_credentials Basic 인증으로만 호출 가능 (token oracle 방지). 캐시
 * 적중률 측정을 위해 같은 token 을 반복 호출하는 시나리오에서 사용.
 */
export function introspectToken(token, hint = 'access_token', tag = 'introspect') {
  const basic = encoding.b64encode(`${CLIENT_ID}:${CLIENT_SECRET}`);
  const body = `token=${encodeURIComponent(token)}&token_type_hint=${hint}`;
  return http.post(`${BASE_URL}/oauth2/introspect`, body, {
    headers: {
      ...formHeaders(),
      Authorization: `Basic ${basic}`,
    },
    tags: { name: tag },
  });
}

/**
 * First-party /api/v1/auth/login — password grant. AuthController.login 참고.
 *
 * 성공 시 200 + body 의 accessToken / refreshToken. MFA 활성 사용자는 401 + X-Mfa-Required
 * (login-refresh 시나리오에서는 비-MFA 사용자만 다룬다).
 */
export function login(tenantSlug, email, password, tag = 'login') {
  const payload = JSON.stringify({ tenantSlug, email, password });
  return http.post(`${BASE_URL}/api/v1/auth/login`, payload, {
    headers: jsonHeaders(),
    tags: { name: tag },
  });
}

/**
 * First-party /api/v1/auth/refresh — refresh rotation.
 *
 * 성공 시 새 access + 새 refresh 발급, 직전 refresh 는 ROTATED 상태로 전환.
 * 회전된 token 을 다시 사용하면 reuse detection 으로 모든 세션 강제 revoke
 * (refresh-reuse-detection 시나리오에서 검증).
 */
export function refresh(refreshToken, tag = 'refresh') {
  const payload = JSON.stringify({ refreshToken });
  return http.post(`${BASE_URL}/api/v1/auth/refresh`, payload, {
    headers: jsonHeaders(),
    tags: { name: tag },
  });
}

/**
 * login → tokens. setup() 단계에서 fixture token 을 미리 확보할 때 사용.
 * 실패 시 throw — k6 의 setup 단계 실패는 시나리오를 abort.
 */
export function loginOrThrow(tenantSlug, email, password) {
  const res = login(tenantSlug, email, password, 'login_setup');
  if (res.status !== 200) {
    throw new Error(`login failed status=${res.status} body=${res.body}`);
  }
  const body = res.json();
  if (!body || !body.accessToken || !body.refreshToken) {
    throw new Error(`login response missing tokens: ${res.body}`);
  }
  return { accessToken: body.accessToken, refreshToken: body.refreshToken };
}

/**
 * client_credentials → access token. setup() 에서 fixture access token 확보.
 */
export function issueAccessTokenOrThrow() {
  const res = issueClientCredentialsToken('token_issue_setup');
  if (res.status !== 200) {
    throw new Error(`client_credentials failed status=${res.status} body=${res.body}`);
  }
  const body = res.json();
  if (!body || !body.access_token) {
    throw new Error(`token response missing access_token: ${res.body}`);
  }
  return body.access_token;
}
