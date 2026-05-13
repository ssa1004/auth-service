// k6 시나리오: POST /oauth2/token (client_credentials grant) 500 req/s 정상 부하.
//
// 측정 의도:
//   JWT 발급 throughput. 본 endpoint 는 client_secret 매칭 (BCrypt 가능) + RS256 서명
//   + claim 조립이 매 호출마다 발생합니다 (read-heavy 와 달리 캐시 가능 자원이 적음).
//   p95 < 100ms 목표 — bcrypt + RS256 sign 시간이 지배적이라 그 이상이면 알고리즘 / CPU
//   튜닝 여지가 있다는 신호.
//
// 실행:
//   k6 run load/k6/scenarios/token-issue.js
//   BASE_URL=http://localhost:8080 CLIENT_ID=... CLIENT_SECRET=... k6 run ...
import { check } from 'k6';
import { issueClientCredentialsToken } from '../lib/oauth.js';

export const options = {
  scenarios: {
    token_issue: {
      executor: 'constant-arrival-rate',
      rate: 500,
      timeUnit: '1s',
      duration: '1m',
      preAllocatedVUs: 100,
      maxVUs: 400,
    },
  },
  thresholds: {
    // bcrypt + RS256 sign — 평상시 p95 100ms 이내. 초과 시 CPU bound / pool 부족 신호.
    'http_req_duration{name:token_issue}': ['p(95)<100'],
    'http_req_failed{name:token_issue}': ['rate<0.01'],
    'checks{name:token_issue}': ['rate>0.99'],
  },
};

export default function () {
  const res = issueClientCredentialsToken('token_issue');
  check(
    res,
    {
      'status 200': (r) => r.status === 200,
      'has access_token': (r) => r.json('access_token') !== undefined,
      'token_type Bearer': (r) => r.json('token_type') === 'Bearer',
      'has expires_in': (r) => r.json('expires_in') !== undefined,
    },
    { name: 'token_issue' }
  );
}
