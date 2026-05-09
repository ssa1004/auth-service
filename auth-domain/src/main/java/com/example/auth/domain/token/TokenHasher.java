package com.example.auth.domain.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Refresh token 평문을 SHA-256 해시로 변환.
 *
 * <p>BCrypt 가 아니라 평범한 hash 인 이유: refresh token 자체가 cryptographically random
 * (>= 256bit) 이라 brute-force 사전 공격이 불가능합니다. BCrypt 는 사람이 만든 약한 secret
 * 을 강화하기 위한 도구이고, 256bit random 값은 hash 한 번이면 충분합니다.
 *
 * <p>또한 refresh 검증은 매 API 요청마다 일어나는 hot path 라 BCrypt cost=12 (~250ms) 는
 * 부담입니다.
 */
public final class TokenHasher {

    private TokenHasher() {
    }

    public static String sha256(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("token 은 비어있을 수 없습니다");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM 에 SHA-256 가 없을 수 없습니다", e);
        }
    }
}
