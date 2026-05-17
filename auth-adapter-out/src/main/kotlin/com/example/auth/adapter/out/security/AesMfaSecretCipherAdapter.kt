package com.example.auth.adapter.out.security

import com.example.auth.application.port.out.MfaSecretCipher
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component

/**
 * AES-GCM 으로 TOTP secret 을 암호화합니다.
 *
 * 키 자료(=master key)는 환경변수 `AUTH_MFA_AES_KEY` (base64, 32 bytes) 로 주입.
 * 운영에서는 KMS / Vault, 개발에서는 application.yml 의 placeholder.
 *
 * 출력 포맷: `iv_base64 + "." + ciphertext_base64` — 한 컬럼에 묶어 저장.
 */
@Component
class AesMfaSecretCipherAdapter(
    @Value("\${auth.mfa.aes-key-base64}") keyBase64: String,
) : MfaSecretCipher {

    private val keySpec: SecretKeySpec = run {
        val key = Base64.getDecoder().decode(keyBase64)
        check(key.size == 32) {
            "AUTH_MFA_AES_KEY 는 base64 디코딩 후 32 bytes 여야 합니다 (실제: ${key.size})"
        }
        SecretKeySpec(key, "AES")
    }

    override fun encrypt(plaintextBase32Secret: String): String {
        val iv = ByteArray(IV_LENGTH)
        RNG.nextBytes(iv)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(TAG_LENGTH, iv))
            val ct = cipher.doFinal(plaintextBase32Secret.toByteArray(StandardCharsets.UTF_8))
            Base64.getEncoder().encodeToString(iv) + "." +
                Base64.getEncoder().encodeToString(ct)
        } catch (e: Exception) {
            throw IllegalStateException("MFA secret 암호화 실패", e)
        }
    }

    override fun decrypt(cipherText: String): String {
        val dot = cipherText.indexOf('.')
        require(dot > 0) { "invalid cipher text" }
        val iv = Base64.getDecoder().decode(cipherText.substring(0, dot))
        val ct = Base64.getDecoder().decode(cipherText.substring(dot + 1))
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(TAG_LENGTH, iv))
            String(cipher.doFinal(ct), StandardCharsets.UTF_8)
        } catch (e: Exception) {
            throw IllegalStateException("MFA secret 복호화 실패", e)
        }
    }

    private companion object {
        const val IV_LENGTH = 12
        const val TAG_LENGTH = 128
        val RNG = SecureRandom()
    }
}
