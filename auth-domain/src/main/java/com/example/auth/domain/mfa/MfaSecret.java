package com.example.auth.domain.mfa;

import com.example.auth.domain.common.UserId;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * 사용자 1인당 최대 1개의 TOTP secret. enable 전까지는 PENDING 상태로 보관됩니다.
 *
 * <p>비밀 자료(=TOTP shared secret) 는 도메인 객체에 *암호화된 상태* 로만 들어옵니다 —
 * application 의 {@code MfaSecretCipher} port 에서 AES 암호화한 결과를 받습니다. 평문
 * secret 은 한 곳 (TOTP 검증 직전) 에서만 잠시 메모리에 존재하고 즉시 폐기됩니다.
 */
public final class MfaSecret {

    private final UUID id;
    private final UserId userId;
    private final String secretCipher;
    private final MfaMethod method;
    private final Instant createdAt;
    private final Instant confirmedAt;

    public MfaSecret(
            UUID id,
            UserId userId,
            String secretCipher,
            MfaMethod method,
            Instant createdAt,
            Instant confirmedAt) {
        this.id = Objects.requireNonNull(id);
        this.userId = Objects.requireNonNull(userId);
        if (secretCipher == null || secretCipher.isBlank()) {
            throw new IllegalArgumentException("secretCipher 는 비어있을 수 없습니다");
        }
        if (secretCipher.length() < 16) {
            // base32 secret 은 통상 32자, AES 암호화 결과는 더 길어집니다. 평문 secret
            // (보통 길이 16) 이 잘못 들어오는 사고를 한 번 더 가드.
            throw new IllegalArgumentException("secretCipher 는 암호화된 값이어야 합니다");
        }
        this.secretCipher = secretCipher;
        this.method = Objects.requireNonNull(method);
        this.createdAt = Objects.requireNonNull(createdAt);
        this.confirmedAt = confirmedAt;
    }

    public static MfaSecret enroll(UserId userId, String secretCipher, MfaMethod method, Instant now) {
        return new MfaSecret(UUID.randomUUID(), userId, secretCipher, method, now, null);
    }

    public MfaSecret confirm(Instant now) {
        return new MfaSecret(id, userId, secretCipher, method, createdAt, now);
    }

    public boolean isConfirmed() {
        return confirmedAt != null;
    }

    public UUID id() { return id; }
    public UserId userId() { return userId; }
    public String secretCipher() { return secretCipher; }
    public MfaMethod method() { return method; }
    public Instant createdAt() { return createdAt; }
    public Instant confirmedAt() { return confirmedAt; }

    /** secretCipher 는 *완전 비공개*. toString 에도 노출하지 않습니다. */
    @Override
    public String toString() {
        return "MfaSecret{userId=" + userId.asString() + ", method=" + method
                + ", confirmed=" + isConfirmed() + "}";
    }
}
