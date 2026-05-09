package com.example.auth.adapter.out.security;

import com.example.auth.application.port.out.RefreshTokenGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.stereotype.Component;

/**
 * CSPRNG 기반 256bit refresh token 평문 생성. URL-safe base64 인코딩.
 */
@Component
public class SecureRandomRefreshTokenGenerator implements RefreshTokenGenerator {

    private static final SecureRandom RNG = new SecureRandom();

    @Override
    public String generate() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
