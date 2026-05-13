// k6 시나리오: refresh token reuse detection invariant 검증 (보안 검증, 부하 아님).
//
// 측정 의도가 부하가 아니라 *invariant*:
//   ADR-0004 / ADR-0015 — 회전된 refresh token 을 두 번째로 사용하면
//     1) 두 번째 호출은 401 (reuse 감지)
//     2) 해당 사용자의 모든 refresh family 가 강제 revoke
//   grace window (5초, refresh-reuse-grace-period) 안에 같은 IP 의 mobile retry 는 보호되지만,
//   본 k6 는 *동일 token 을 의도적으로 2회 사용* 하는 케이스 — grace 와 무관하게 reuse 로
//   판정되어야 합니다.
//
// 흐름:
//   1) login 으로 refresh1 발급
//   2) refresh1 으로 회전 — refresh2 발급 (200)
//   3) refresh1 을 다시 사용 — 401 + family revoke 트리거 기대 (invariant)
//   4) refresh2 를 다시 사용 — 위 family revoke 가 반영되어 401 기대 (전 family revoke 검증)
//
// 실행:
//   k6 run load/k6/scenarios/refresh-reuse-detection.js
//
// VU 1 / iteration N — 매 iteration 마다 새 login 으로 새 family 를 만들어 독립 검증.
import { check, group } from 'k6';
import { login, refresh } from '../lib/oauth.js';
import {
  TENANT_SLUG,
  USER_EMAIL,
  USER_PASSWORD,
} from '../lib/config.js';

const ITERATIONS = parseInt(__ENV.ITERATIONS || '20', 10);

export const options = {
  scenarios: {
    reuse_detection: {
      executor: 'shared-iterations',
      vus: 1,
      iterations: ITERATIONS,
      maxDuration: '5m',
    },
  },
  thresholds: {
    // 부하가 아니므로 latency 임계는 느슨하게.
    'http_req_failed{name:reuse_login}':   ['rate<0.05'],
    // invariant check 4종 (rotate_ok / reuse_401 / family_revoked / login_ok) 이 모두
    // 100% 통과해야 한다.
    'checks{name:reuse_login}':            ['rate==1.0'],
    'checks{name:reuse_rotate_ok}':        ['rate==1.0'],
    'checks{name:reuse_second_use_401}':   ['rate==1.0'],
    'checks{name:reuse_family_revoked}':   ['rate==1.0'],
  },
};

export default function () {
  group('reuse_detection_flow', function () {
    // 1) login → refresh1
    const loginRes = login(TENANT_SLUG, USER_EMAIL, USER_PASSWORD, 'reuse_login');
    const okLogin = check(
      loginRes,
      { 'login 200 + tokens': (r) => r.status === 200 && r.json('refreshToken') !== undefined },
      { name: 'reuse_login' }
    );
    if (!okLogin) return;
    const refresh1 = loginRes.json('refreshToken');

    // 2) refresh1 회전 → refresh2 (정상 흐름)
    const rotateRes = refresh(refresh1, 'reuse_rotate');
    const okRotate = check(
      rotateRes,
      {
        'rotate 200': (r) => r.status === 200,
        'new refreshToken': (r) => {
          const v = r.json('refreshToken');
          return v !== undefined && v !== refresh1;
        },
      },
      { name: 'reuse_rotate_ok' }
    );
    if (!okRotate) return;
    const refresh2 = rotateRes.json('refreshToken');

    // 3) refresh1 재사용 — 401 + family revoke 트리거 기대 (invariant)
    const reuseRes = refresh(refresh1, 'reuse_second_use');
    check(
      reuseRes,
      { 'reuse → 401': (r) => r.status === 401 },
      { name: 'reuse_second_use_401' }
    );

    // 4) 정상 회전했던 refresh2 도 family revoke 로 401 기대 (전 family revoke invariant)
    const followUp = refresh(refresh2, 'reuse_family_check');
    check(
      followUp,
      { 'family revoked → 401': (r) => r.status === 401 },
      { name: 'reuse_family_revoked' }
    );
  });
}
