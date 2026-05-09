package com.example.auth.domain.user;

public enum MfaStatus {
    /** MFA 미설정. 비밀번호만으로 로그인 완료. */
    DISABLED,
    /** secret 발급 + QR 표시까지 끝났으나 첫 코드 검증이 아직 안 됨. */
    PENDING,
    /** secret 등록 + 첫 코드 검증 완료. 로그인 시 TOTP 단계 강제. */
    ENABLED
}
