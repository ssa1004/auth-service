package com.example.auth.adapter.out.security;

import com.example.auth.application.port.out.PasswordHasher;
import com.example.auth.application.security.AuthProperties;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * BCrypt 구현체. cost 는 {@link AuthProperties#bcryptCost()} (기본 12).
 *
 * <p>cost=12 는 2026년 기준 ~250ms (M1) — 사용자 체감 한계 + brute force 방어 사이의 정책
 * 결정. ADR-0001 / ADR-0007 참고.
 */
@Component
public class BCryptPasswordHasherAdapter implements PasswordHasher {

    private final BCryptPasswordEncoder encoder;

    public BCryptPasswordHasherAdapter(AuthProperties properties) {
        this.encoder = new BCryptPasswordEncoder(properties.bcryptCost());
    }

    @Override
    public String hash(String rawPassword) {
        return encoder.encode(rawPassword);
    }

    @Override
    public boolean matches(String rawPassword, String hash) {
        return encoder.matches(rawPassword, hash);
    }
}
