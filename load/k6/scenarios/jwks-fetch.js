// k6 시나리오: GET /oauth2/jwks (정적 JWK Set) 2000 req/s.
//
// 측정 의도:
//   Resource Server 들이 JWT 서명을 검증할 때 가장 빈번하게 호출하는 endpoint.
//   응답 body 는 거의 정적 (24h JWK rotation cycle 안에서는 동일) 이라 캐싱 / CDN /
//   reverse-proxy 가 동작한다면 p95 < 10ms 가 목표입니다. 초과 시 캐시 무효 / 매 호출
//   JWKSet 직렬화 의심.
//
//   Note: 본 codebase 의 실제 endpoint 는 /oauth2/jwks (Spring Authorization Server 1.4).
//   /.well-known/jwks.json 으로 매핑하고 싶다면 JWKS_URL 환경 변수로 override.
//
// 실행:
//   k6 run load/k6/scenarios/jwks-fetch.js
//   JWKS_URL=http://localhost:8080/.well-known/jwks.json k6 run ...
import http from 'k6/http';
import { check } from 'k6';
import { JWKS_URL } from '../lib/config.js';

export const options = {
  scenarios: {
    jwks: {
      executor: 'constant-arrival-rate',
      rate: 2000,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 100,
      maxVUs: 500,
    },
  },
  thresholds: {
    // 정적 응답 + 캐싱 — p95 < 10ms.
    'http_req_duration{name:jwks}': ['p(95)<10'],
    'http_req_failed{name:jwks}': ['rate<0.001'],
    'checks{name:jwks}': ['rate>0.99'],
  },
};

export default function () {
  const res = http.get(JWKS_URL, { tags: { name: 'jwks' } });
  check(
    res,
    {
      'status 200': (r) => r.status === 200,
      'has keys[]': (r) => {
        try {
          const body = r.json();
          return body && Array.isArray(body.keys) && body.keys.length > 0;
        } catch (_) {
          return false;
        }
      },
      // current + previous (grace) 두 키가 노출되는지 — JWK rotation 직후 검증.
      // 회전 안 한 상태에서는 1개도 정상이므로 strict 검증은 하지 않음 (>= 1).
      'kid 존재': (r) => {
        try {
          return r.json('keys.0.kid') !== undefined;
        } catch (_) {
          return false;
        }
      },
    },
    { name: 'jwks' }
  );
}
