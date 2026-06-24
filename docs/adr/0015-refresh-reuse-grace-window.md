# ADR-0015: Refresh token reuse detection 의 grace window

## 상태
적용

## 배경

ADR-0004 의 reuse detection 은 이미 회전된 token 이 다시 들어오면 사용자의 모든 세션을
강제 revoke 합니다. 토큰 탈취 시나리오 (공격자가 훔친 token 으로 refresh 시도) 에는
강력한 방어선입니다.

문제는 정상 mobile client 도 같은 token 을 두 번 보내는 경우가 종종 있다는 점입니다.

- 모바일 네트워크 jitter — refresh 요청이 timeout 되면 client 는 같은 token 으로 재시도
- 백그라운드 task 와 포그라운드 task 가 동시에 refresh 시도
- HTTP/2 stream 재전송

이 정상 retry 가 reuse detection 에 잡히면 사용자가 앱을 켤 때마다 모든 디바이스에서
강제 로그아웃되는 사고가 됩니다. 사용자 입장에서는 "왜 자꾸 로그인하라고 해요" 라는
컴플레인으로 이어집니다.

## 결정

### grace window — 회전 직후 짧은 시간은 정당한 retry 로 간주

`RefreshToken` 에 `isWithinReuseGrace(now, graceWindow, sameNetwork)` 를 추가합니다.
`RefreshTokenService` 가 reuse signal 을 감지하면 바로 revoke 하지 않고 두 조건을
검사합니다.

1. **시간**: `(now - lastUsedAt) <= graceWindow` (기본 5초, `auth.refresh-reuse-grace-period` 로 조절)
2. **네트워크**: 호출 IP 가 token 발급 시 IP 와 같음

둘 다 만족하면 grace 로 처리. 401 (`InvalidCredentialsException`) 만 반환하고 revoke 는
하지 않습니다. 정상 client 는 자기가 받은 새 refresh token 으로 재시도하면 됩니다.

둘 중 하나라도 안 맞으면 진짜 reuse 로 간주하여 일괄 revoke + reuse audit 를 수행합니다.

### 왜 5초

- 너무 좁으면 정상 mobile retry 도 잡혀 사용자 사고가 납니다.
- 너무 넓으면 진짜 탈취 시 공격자에게 유효한 retry 시간을 주게 됩니다.
- 외부 IdP 들이 권장하는 범위 (10~60s) 의 짧은 쪽. 본 도메인의 모바일 retry 는 보통
  1~3초 안에 끝나기 때문입니다.

### 왜 IP 까지 보나

시간만 보면 공격자가 훔친 token 을 회전 직후 (5초 안) 사용해도 grace 처리되어 버립니다.
IP 조건을 추가해서 같은 IP 가 아니면 grace 를 적용하지 않습니다. 모바일 cellular ↔ wifi
전환 시 IP 가 바뀌긴 하지만, 그 케이스는 대부분 새 refresh 로 retry 하므로 grace 가
필요한 시나리오 자체가 아닙니다.

userAgent 도 추가 검증할 수 있지만, 같은 앱이라도 OS 업데이트 / SDK rotation 으로 UA 가
바뀔 수 있어 false negative 위험이 있어 IP 만 사용합니다.

### grace 처리도 audit 에 남기나

남기지 않습니다. grace 는 정상 client 의 정상 retry 라서, audit 에 기록하면 SIEM 알람이
노이즈로 가득 차게 됩니다. 진짜 reuse (grace 밖) 만 audit 합니다.

### 시나리오: 공격자가 훔친 token 을 회전 직후 사용

공격자가 사용자의 refresh token 을 훔쳐 회전 직후 (3초 후) 사용하더라도, IP 가 다르므로
grace 조건을 통과하지 못해 즉시 reuse 로 처리됩니다. 사용자의 모든 세션이 revoke 되고
audit + 알람이 발생합니다.

## 대안

### grace 자체 안 함
탈락. 모바일 client 의 실제 retry 빈도가 높아 사용자 사고가 자주 발생합니다 (위 배경
참조).

### grace 안에서는 새 refresh 도 재발급
검토했지만 탈락. child token 의 평문을 다시 알려줘야 하는데 우리는 hash 만 보관합니다.
재발급하려면 새 token 발행 → audit 복잡 + race 위험. 단순 401 이 더 깔끔합니다.

### grace window 를 client 별 동적으로
탈락. 운영 복잡. 5초 fixed 로 충분합니다. 클라이언트가 5초 안에 회복하지 못하면 어차피
사용자 경험이 망가져 grace 가 의미 없어집니다.

## 결과

- 정상 mobile retry → revoke 하지 않고 사용자 경험을 보호.
- 진짜 reuse (grace 밖 또는 다른 IP) → 즉시 revoke + audit.
- (단점) IP 가 변경된 정상 client 의 회전 직후 retry 는 즉시 revoke 됩니다. Cellular ↔
  wifi 전환의 그 찰나에 retry 한 사용자는 강제 로그아웃됩니다. 빈도는 낮을 것으로
  가정합니다.
- (단점) grace window 안의 공격자 시도는 silent fail 이라 사용자에게 알릴 방법이
  없습니다. 다만 공격자가 유효한 token 을 한 번 사용해야 trigger 되는 시나리오이므로 추가
  침해 진입은 없습니다.

## 후속

- IP 매칭 정밀도 — `/24` subnet 단위 매칭 (사용자 IP 가 변동 작은 ISP 에 있으면 grace 친화적)
- grace window 동적 — 사용자 last-known device 별 jitter profile 학습 (운영 데이터 누적 후)
- mobile SDK 가이드 — grace 안에서 401 받으면 *바로 새 refresh 로 한 번 더* retry 하도록 표준 동작 명시

## 용어 풀이 (쉽게)

- **grace window (재사용 유예)** — 정상 앱도 네트워크가 끊기면 같은 출입증을 두 번 보낸다. 회전 직후 짧은 시간(5초) + 같은 IP면 '탈취 아닌 정상 재시도'로 봐주고 강제 로그아웃 대신 그냥 401만 돌려주는 봐주기 구간.
- **reuse detection (재사용 탐지)** — 이미 폐기된 옛 출입증이 다시 들어오면 '훔쳐 쓰는 중'으로 의심해 그 사용자의 모든 세션을 무효화하는 방어. grace는 이걸 너무 빡빡하게 적용하지 않으려는 완충이다.
- **false negative (놓침)** — 진짜 잡아야 할 걸 못 잡는 오류. 여기선 userAgent로 검증하면 정상 앱이 OS 업데이트로 UA가 바뀌었을 때 정상인데도 탈취로 오인할 위험이 있어 IP만 쓴다.
- **silent fail (조용한 실패)** — 사용자에게 따로 알리지 않고 그냥 401만 떨어뜨리는 처리. grace 안에서는 정상 재시도일 가능성이 높아 시끄러운 알람을 안 울린다.
