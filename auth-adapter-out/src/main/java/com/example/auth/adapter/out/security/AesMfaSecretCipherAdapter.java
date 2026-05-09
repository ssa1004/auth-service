package com.example.auth.adapter.out.security;

import com.example.auth.application.port.out.MfaSecretCipher;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * AES-GCM 으로 TOTP secret 을 암호화합니다.
 *
 * <p>키 자료(=master key)는 환경변수 {@code AUTH_MFA_AES_KEY} (base64, 32 bytes) 로 주입.
 * 운영에서는 KMS / Vault, 개발에서는 application.yml 의 placeholder.
 *
 * <p>출력 포맷: {@code iv_base64 + "." + ciphertext_base64} — 한 컬럼에 묶어 저장.
 */
@Component
public class AesMfaSecretCipherAdapter implements MfaSecretCipher {

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 128;
    private static final SecureRandom RNG = new SecureRandom();

    private final SecretKeySpec keySpec;

    public AesMfaSecretCipherAdapter(@Value("${auth.mfa.aes-key-base64}") String keyBase64) {
        byte[] key = Base64.getDecoder().decode(keyBase64);
        if (key.length != 32) {
            throw new IllegalStateException(
                    "AUTH_MFA_AES_KEY 는 base64 디코딩 후 32 bytes 여야 합니다 (실제: " + key.length + ")");
        }
        this.keySpec = new SecretKeySpec(key, "AES");
    }

    @Override
    public String encrypt(String plaintextBase32Secret) {
        byte[] iv = new byte[IV_LENGTH];
        RNG.nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(TAG_LENGTH, iv));
            byte[] ct = cipher.doFinal(plaintextBase32Secret.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(iv) + "."
                    + Base64.getEncoder().encodeToString(ct);
        } catch (Exception e) {
            throw new IllegalStateException("MFA secret 암호화 실패", e);
        }
    }

    @Override
    public String decrypt(String cipherText) {
        int dot = cipherText.indexOf('.');
        if (dot <= 0) throw new IllegalArgumentException("invalid cipher text");
        byte[] iv = Base64.getDecoder().decode(cipherText.substring(0, dot));
        byte[] ct = Base64.getDecoder().decode(cipherText.substring(dot + 1));
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(TAG_LENGTH, iv));
            return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("MFA secret 복호화 실패", e);
        }
    }
}
