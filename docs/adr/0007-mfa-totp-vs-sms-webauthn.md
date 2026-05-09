# ADR-0007: 2FA — TOTP 선택 (vs SMS / Email OTP / WebAuthn)

## 상태
적용

## 배경
2FA 채널 후보:

- **SMS OTP** — 친숙. 단 SIM swap 공격, 통신사 비용, 국가별 도달성 격차.
- **Email OTP** — 메일 계정이 1차 인증과 같으면 사실상 1FA. 별도 메일 계정이라도 메일이
  가장 자주 침해되는 채널.
- **TOTP** (RFC 6238) — Google Authenticator 류. 오프라인 동작, 비용 0, 표준.
- **WebAuthn / FIDO2** — 가장 강한 옵션. 단 디바이스 등록 / 복구 흐름이 복잡.
- **Push (앱)** — UX 좋음. 단 자체 앱 또는 IdP 벤더 의존성 (Authy, Duo) 필요.

## 결정
**1차로 TOTP (RFC 6238)**. WebAuthn 은 후속 ADR.

이유:
1. 운영 비용 0 — SMS gateway / 메일 templates / 자체 앱 모두 불필요.
2. 표준 준수 — 어떤 authenticator 앱이든 동작 (Google Authenticator, Authy, 1Password,
   Bitwarden).
3. 오프라인 동작 — 통신 장애 / 비행기 모드에서도 인증 가능.
4. secret 자체는 *AES-GCM 암호화* 하여 DB 보관 — 키 자료 (master key) 는 환경변수 /
   KMS 외부 주입.

구현:
- 라이브러리: `dev.samstevens.totp` (RFC 6238 준수, 단순 API).
- secret 길이 32자 base32 (= 160bit), SHA-1 / 30s window / 6 digits (Google Authenticator
  호환).
- verify 시 ±1 step (=±30초) 시계 어긋남 허용.
- 등록 시 첫 코드 검증 통과까지 `MfaStatus.PENDING`. 검증 통과 후 `ENABLED`.

## 결과
- TOTP secret 한 번 등록하면 사용자 디바이스 분실 시 재등록 흐름이 까다로움 — 복구 코드
  (one-time recovery codes) 발급 흐름 추가 검토 필요.
- (단점) 사용자 시계 / 서버 시계 어긋남이 ±60초 넘으면 검증 실패 — NTP 동기화 모니터링.
- (단점) authenticator 앱이 깔린 디바이스 자체가 침해되면 1FA 와 같은 강도 — WebAuthn
  하드웨어 키가 더 강함.

## 다시 검토할 시점
- WebAuthn (passkey) 도입 — 디바이스 등록 / fallback 정책 확정 후 별도 ADR.
- 사용자가 디바이스 분실로 재로그인 못 하는 사고가 일정 비율 이상 발생 → 복구 흐름 ADR.
