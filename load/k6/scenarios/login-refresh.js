// k6 시나리오: POST /auth/login → POST /auth/refresh (refresh rotation) ramping 0 → 100 VU.
//
// 측정 의도:
//   end-user 흐름의 정상 부하. 한 VU 가 login 으로 token 한 쌍을 받고, 같은 iteration 안에서
//   refresh 회전을 한 번 호출합니다. login (BCrypt verify + RS256 sign + DB write) 과
//   refresh (DB select + rotate + Redis grace) 두 단계의 latency 를 같이 본다.
//
//   p95 < 150ms, error < 1% 가 목표. ramping-vus 로 0 에서 100 VU 까지 올려가며 점진적
//   부하 — auto-scaling / 연결 풀 워밍업 거동 확인용.
//
// 사전 준비:
//   USER_EMAIL / USER_PASSWORD / TENANT_SLUG 의 사용자가 이미 register 되어 있어야 함.
//   docker-compose 환경에서는 직접 /api/v1/auth/register 로 시드를 만들어 두어야 합니다.
//
// 실행:
//   k6 run load/k6/scenarios/login-refresh.js
import { check, group } from 'k6';
import {
  login,
  refresh,
} from '../lib/oauth.js';
import {
  TENANT_SLUG,
  USER_EMAIL,
  USER_PASSWORD,
} from '../lib/config.js';

export const options = {
  scenarios: {
    login_refresh: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 50 },   // ramp up — 워밍업 / pool 안정화
        { duration: '1m',  target: 100 },  // ramp up to peak
        { duration: '1m',  target: 100 },  // sustain peak
        { duration: '30s', target: 0 },    // ramp down
      ],
      gracefulRampDown: '15s',
    },
  },
  thresholds: {
    // login + refresh 묶음 — login 이 BCrypt 라 100ms 이상은 정상. 합쳐서 p95 < 150ms.
    'http_req_duration{name:login}':   ['p(95)<150'],
    'http_req_duration{name:refresh}': ['p(95)<150'],
    'http_req_failed{name:login}':   ['rate<0.01'],
    'http_req_failed{name:refresh}': ['rate<0.01'],
    'checks{name:login_refresh_flow}': ['rate>0.99'],
  },
};

export default function () {
  group('login_refresh_flow', function () {
    const loginRes = login(TENANT_SLUG, USER_EMAIL, USER_PASSWORD, 'login');
    const loginOk = check(
      loginRes,
      {
        'login 200': (r) => r.status === 200,
        'has accessToken': (r) => r.json('accessToken') !== undefined,
        'has refreshToken': (r) => r.json('refreshToken') !== undefined,
      },
      { name: 'login_refresh_flow' }
    );
    if (!loginOk) return;

    const refreshToken = loginRes.json('refreshToken');
    const refreshRes = refresh(refreshToken, 'refresh');
    check(
      refreshRes,
      {
        'refresh 200': (r) => r.status === 200,
        'rotated accessToken': (r) => r.json('accessToken') !== undefined,
        'rotated refreshToken': (r) => {
          const rotated = r.json('refreshToken');
          // 회전된 token 이 직전 값과 달라야 한다 — rotation 검증.
          return rotated !== undefined && rotated !== refreshToken;
        },
      },
      { name: 'login_refresh_flow' }
    );
  });
}
