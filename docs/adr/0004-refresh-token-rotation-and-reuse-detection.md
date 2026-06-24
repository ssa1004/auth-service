# ADR-0004: Refresh token rotation + reuse detection

## 상태
적용

## 배경
Refresh token 의 수명은 길고 (30일) 평문 자체가 인증 자료입니다. 클라이언트 저장소가
탈취되면 (XSS, malware, 백업 유출) 공격자가 access token 을 무제한 갱신할 수 있습니다.

전통적인 고정 refresh token (한 번 받으면 30일 동안 같은 값) 은 탈취가 일어나도 그 사실을
끝내 알 수 없습니다.

## 결정
**Refresh token rotation + reuse detection**.

흐름:
1. `/refresh` 호출마다 새 refresh token 을 발행하고, 기존 token 은 `REVOKED_ROTATED` 로
   마킹합니다.
2. 마킹된 token 이 다시 들어오면 reuse signal 로 간주. 사용자의 모든 refresh 를
   `REVOKED_REUSE_DETECTED` 로 일괄 revoke + audit + 401.
3. 사용자는 재로그인 강제.

이 패턴은 RFC 6749 §10.4 가 권고하고, Auth0 / Okta 등의 IdP 에서 reference implementation
으로 정리되어 있습니다.

구현 핵심:
- 평문 token 은 DB / 로그 / audit 에 절대 저장 금지. SHA-256 hash 만 보관 (`tokenHash`
  unique).
- DB lookup 은 `findByTokenHashForUpdate` 로 비관적 잠금. READ COMMITTED 에서 같은 hash
  가 동시에 두 번 들어올 때 race 를 차단합니다.
- reuse 일괄 revoke 시 `REVOKED_REUSE_DETECTED` 와 `REVOKED_BY_USER` 는 제외 — 이미
  처리된 사고나 사용자 의사를 덮어쓰지 않기 위함.

평문 hash 를 BCrypt 가 아니라 SHA-256 으로 두는 이유:
- refresh token 평문은 256bit CSPRNG — 사람이 만든 약한 비밀이 아니라 brute-force 방어가
  필요 없습니다.
- BCrypt cost=12 (~250ms) 를 매 API 요청 hot path 에서 돌리는 부담을 피합니다.

## 결과
- 탈취 사고가 대부분 자동 탐지됩니다. 공격자가 한 번이라도 회전을 시키면 정상 사용자가
  다음 호출 때 reuse signal 을 발동시킵니다.
- 사용자가 평소처럼 사용하던 디바이스에서도 갑자기 모두 로그아웃되는 일이 생길 수 있어,
  사용자에게 왜 로그아웃되었는지 알리는 알림 / 세션 관리 페이지가 필요합니다 (ADR-0008
  audit 와 연동).
- (단점) 같은 디바이스에서 동시 호출 (mobile 의 두 thread / 브라우저 다중 탭) 이 race 로
  reuse 에 잡힐 수 있어 `refreshReuseGracePeriod` 5초 grace 를 도입했습니다 (ADR-0015).
- (단점) refresh 호출마다 DB 쓰기 1회. 분당 수천 요청 규모면 read replica 분리를
  검토합니다.

## 용어 풀이 (쉽게)

- **refresh token rotation (회전)** — 장기 출입증(refresh token)을 쓸 때마다 새것으로 바꾸고 옛것은 폐기. 번호가 계속 바뀌는 일회용 비밀번호처럼.
- **reuse detection + family revoke (재사용 탐지·일괄 무효화)** — 이미 폐기된 옛 출입증이 다시 들어오면 '누가 훔쳐 쓰는 중'으로 의심해 그 사용자의 출입증을 전부 한꺼번에 무효화. 카드 복제가 의심되면 그 사람 카드를 모두 정지하는 것.
- **SHA-256 hash 저장 (평문 미저장)** — 출입증 원본은 DB에 안 넣고 한 방향으로 갈아버린 지문(해시)만 저장. DB가 통째로 유출돼도 지문만으론 원본을 못 만든다.
- **비관적 락 (FOR UPDATE)** — 같은 출입증이 동시에 두 번 들어올 때 먼저 들어온 쪽이 그 행을 통째로 잠그고 처리. 화장실 문 잠그고 들어가듯 다음 사람은 끝날 때까지 대기.
- **CSPRNG (암호학적 난수)** — 사람이 만든 약한 비밀번호가 아니라 예측 불가능하게 무작위로 뽑은 256bit 값. 무차별 대입으로 못 맞혀 BCrypt 같은 느린 해시 없이 빠른 SHA-256으로 충분하다.
