// k6 시나리오: POST /oauth2/introspect (RFC 7662) 1000 req/s 정상 부하.
//
// 측정 의도:
//   Read-heavy 시나리오. 같은 token 을 반복 호출하므로 Redis 기반 introspect 캐시 (있다면)
//   적중률이 매우 높아야 합니다. p95 < 20ms 가 목표 — JWT 서명 재검증 / DB 조회까지
//   가면 그 이상.
//
//   custom 메트릭 `introspect_active_rate` 로 active=true 비율 측정 — 캐시 / 정상 흐름
//   확인용 (모두 동일 fixture token 이므로 일관적으로 true 여야 함).
//
// 실행:
//   k6 run load/k6/scenarios/token-introspect.js
import { check } from 'k6';
import { Rate } from 'k6/metrics';
import {
  issueAccessTokenOrThrow,
  introspectToken,
} from '../lib/oauth.js';

const introspectActiveRate = new Rate('introspect_active_rate');

export const options = {
  scenarios: {
    introspect: {
      executor: 'constant-arrival-rate',
      rate: 1000,
      timeUnit: '1s',
      duration: '1m',
      preAllocatedVUs: 100,
      maxVUs: 500,
    },
  },
  thresholds: {
    // Redis 캐시 적중 시 p95 < 20ms. 초과 시 캐시 miss 비율 / Redis RTT 의심.
    'http_req_duration{name:introspect}': ['p(95)<20'],
    'http_req_failed{name:introspect}': ['rate<0.01'],
    'introspect_active_rate': ['rate>0.99'],   // fixture token 은 항상 active 여야 함
    'checks{name:introspect}': ['rate>0.99'],
  },
};

export function setup() {
  // 부하 본문에서 매 iteration 마다 token 을 새로 발급하면 introspect 측정이 token 발급
  // 비용에 묻혀버립니다. 고정 token 한 개를 사전 발급해 캐시 적중 시나리오를 만든다.
  const token = issueAccessTokenOrThrow();
  return { token };
}

export default function (data) {
  const res = introspectToken(data.token, 'access_token', 'introspect');
  const active = res.json && res.json('active');
  introspectActiveRate.add(active === true);
  check(
    res,
    {
      'status 200': (r) => r.status === 200,
      'active=true': (r) => r.json('active') === true,
    },
    { name: 'introspect' }
  );
}
