# ADR-0015: Refresh token reuse detection 의 grace window

## 상태
적용

## 배경

ADR-0004 의 reuse detection (Auth0 패턴) 은 *이미 회전된 token 이 다시 들어오면 사용자의
모든 세션 강제 revoke* 한다. 토큰 탈취 시나리오 (공격자가 훔친 token 으로 refresh 시도) 에
강력한 방어선.

문제: *정상* mobile client 도 같은 token 을 두 번 보내는 경우가 종종 있다.

- 모바일 네트워크 jitter — refresh 요청이 timeout 되면 client 는 같은 token 으로 재시도
- 백그라운드 task / 포그라운드 task 가 동시에 refresh 시도
- HTTP/2 stream 재전송

이 정상 retry 가 reuse detection 에 잡히면 — 사용자가 앱을 켤 때마다 *모든 디바이스에서
강제 로그아웃* 되는 사고. 사용자 입장에서는 "왜 자꾸 로그인하라고 해요" 컴플레인.

## 결정

### grace window — 회전 직후 짧은 시간은 정당한 retry 로 간주

`RefreshToken` 에 `isWithinReuseGrace(now, graceWindow, sameNetwork)` 추가.
`RefreshTokenService` 가 reuse signal 을 감지하면 *바로 revoke* 하지 않고 두 조건 검사:

1. **시간**: `(now - lastUsedAt) <= graceWindow` (기본 5초, `auth.refresh-reuse-grace-period` 로 조절)
2. **네트워크**: 호출 IP 가 token 발급 시 IP 와 같음

둘 다 만족 → grace 처리. **401 (`InvalidCredentialsException`)** 만 반환하고 revoke 안 함.
정상 client 는 자기가 받은 *새* refresh token 으로 재시도하면 됨.

둘 중 하나라도 안 맞음 → 진짜 reuse 로 간주, 일괄 revoke + reuse audit (Auth0 패턴 그대로).

### 왜 5초

- 너무 좁으면 정상 mobile retry 도 잡혀 사용자 사고
- 너무 넓으면 진짜 탈취 시 공격자에게 유효한 retry 시간을 줌
- Auth0 / Okta 가 권장하는 범위 (10~60s) 의 짧은 쪽 — 본 도메인은 모바일 retry 가 보통 1~3초 안에 끝남

### 왜 IP 까지 보나

시간만 보면 — 공격자가 *훔친 token* 을 회전된 직후 (5초 안) 사용해도 grace 처리됨. IP
조건 추가 → 같은 IP 가 아니면 grace 안 함. 모바일 cellular ↔ wifi 전환 시 IP 가 바뀌긴
하지만, 그 케이스는 *대부분 새 refresh 로 retry* 라 grace 가 필요한 시나리오 자체가 아님.

userAgent 도 추가 검증 가능하지만, 같은 앱이라도 OS 업데이트 / SDK rotation 으로 UA 가
바뀔 수 있어 false negative 위험. IP 만 사용.

### grace 처리도 audit 에 남기나

남기지 *않음*. grace 는 정상 client 의 정상 retry — audit 에 박으면 SIEM 알람이 노이즈로
가득 참. 진짜 reuse (grace 밖) 만 audit.

## 대안

### grace 자체 안 함 (Auth0 default)
탈락 — 모바일 client 의 실제 retry 빈도가 높아 사용자 사고 다발 (위 배경 참조).

### grace 안에서는 새 refresh 도 재발급
검토했지만 탈락 — child token 의 *평문* 을 다시 알려줘야 하는데 우리는 hash 만 보관.
재발급하려면 새 token 발행 → audit 복잡 + race 위험. 단순 401 이 더 깔끔.

### grace window 를 client 별 동적으로
탈락 — 운영 복잡. 5초 fixed 로 충분. 클라이언트가 5초 안에 회복 못 하면 어차피 사용자
경험 망가져 grace 무의미.

## 결과

- 정상 mobile retry → revoke 안 함, 사용자 경험 보호
- 진짜 reuse (grace 밖 또는 다른 IP) → 즉시 revoke + audit
- (단점) IP 변경된 정상 client 의 회전 직후 retry → 즉시 revoke. Cellular ↔ wifi 전환의 *그
  찰나* 에 retry 한 사용자가 강제 로그아웃. 빈도 낮을 것으로 가정.
- (단점) grace window 안 공격자 시도는 silent fail — 사용자에게 알릴 방법 없음. 그래도
  공격자가 *유효한 token* 을 한 번 사용했어야 trigger 되는 시나리오라 침해 진입은 없음.

## 후속

- IP 매칭 정밀도 — `/24` subnet 단위 매칭 (사용자 IP 가 변동 작은 ISP 에 있으면 grace 친화적)
- grace window 동적 — 사용자 last-known device 별 jitter profile 학습 (운영 데이터 누적 후)
- mobile SDK 가이드 — grace 안에서 401 받으면 *바로 새 refresh 로 한 번 더* retry 하도록 표준 동작 명시
