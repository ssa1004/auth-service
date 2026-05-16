package com.example.auth.application.port.out

/**
 * TOTP secret 암복호화 port. 구현체는 AES-GCM 권장 (adapter-out).
 *
 * 평문 secret 은 한 곳에서만 잠시 메모리에 등장해야 합니다 — TOTP 검증 직전. DB / 로그
 * / audit / response 어디에도 평문이 흘러가면 안 됩니다.
 */
interface MfaSecretCipher {

    fun encrypt(plaintextBase32Secret: String): String

    fun decrypt(cipherText: String): String
}
