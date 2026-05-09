# ADR-0004: Refresh token rotation + reuse detection (Auth0 패턴)

## 상태
적용

## 배경
Refresh token 의 수명은 길고 (30일) 평문 자체가 인증 자료입니다. 클라이언트 저장소가
탈취되면 (XSS, malware, 백업 유출) 공격자가 access token 을 무제한 갱신할 수 있습니다.

전통적인 *고정 refresh token* (한 번 받으면 30일 같은 값) 은 탈취 사실을 *영영 알 수 없습니다*.

## 결정
**Refresh token rotation + reuse detection** (Auth0 가 정리한 패턴).

흐름:
1. `/refresh` 호출마다 새 refresh token 발행 + 기존 token 은 `REVOKED_ROTATED` 로 마킹.
2. 마킹된 token 이 *다시* 들어오면 → reuse signal. 사용자의 *모든* refresh 를
   `REVOKED_REUSE_DETECTED` 로 일괄 revoke + audit + 401.
3. 사용자는 재로그인 강제.

구현 핵심:
- 평문 token 은 DB / 로그 / audit 에 절대 저장 금지. SHA-256 hash 만 보관 (`tokenHash`
  unique).
- DB lookup 은 `findByTokenHashForUpdate` 로 비관적 잠금 (READ COMMITTED 에서 같은 hash
  가 동시에 두 번 들어올 때 race 차단).
- reuse 일괄 revoke 는 `REVOKED_REUSE_DETECTED` 와 `REVOKED_BY_USER` 는 제외 — 이미
  처리된 사고 / 사용자 의사를 덮어쓰지 않음.

왜 평문 hash 가 BCrypt 가 아니라 SHA-256 인가:
- refresh token 평문은 256bit CSPRNG — 사람이 만든 약한 비밀이 아니라 brute-force 방어가
  필요 없음.
- BCrypt cost=12 (~250ms) 를 매 API 요청 hot path 에서 돌리는 부담을 피함.

## 결과
- 탈취 사고가 *대부분* 자동 탐지 (공격자가 한 번이라도 회전 시키면 합법 사용자가 다음 호출
  때 reuse signal 발동).
- 사용자가 평소처럼 사용하던 디바이스에서도 갑자기 모두 logout 되는 일이 생길 수 있음 —
  사용자에게 *왜 logout 되었는지* 알리는 알림 / 세션 관리 페이지 (ADR-0008 audit 와 연동).
- (단점) 같은 디바이스에서 동시 호출 (mobile 의 두 thread / 브라우저 다중 탭) 이 race 로
  reuse 로 잡힐 수 있음 — `refreshReuseGracePeriod` 5초 grace 도입 (현재 5초, 추후 조정).
- (단점) refresh 호출 hop 마다 DB 쓰기 1회 — 분당 수천 요청 규모면 read replica 분리
  검토.
