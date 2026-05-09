package com.example.auth.application.port.out;

/**
 * RFC 6238 TOTP 검증 port. window 는 ±1 step (=30초) 권장.
 *
 * <p>secret 은 base32 평문이며, application 이 호출 직전에 {@link MfaSecretCipher} 로
 * 풀어 넘깁니다.
 */
public interface TotpVerifier {

    /** 새 secret 생성 (등록 흐름). base32 인코딩된 평문 반환. */
    String generateSecret();

    /** 등록 화면용 QR otpauth URL. (테스트에서는 사용 안 해도 됨) */
    String otpAuthUrl(String label, String issuer, String secret);

    /** 사용자 입력 코드 검증. true / false. */
    boolean verify(String secret, String code);
}
