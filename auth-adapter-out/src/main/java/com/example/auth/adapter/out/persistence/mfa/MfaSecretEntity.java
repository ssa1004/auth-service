package com.example.auth.adapter.out.persistence.mfa;

import com.example.auth.domain.common.UserId;
import com.example.auth.domain.mfa.MfaMethod;
import com.example.auth.domain.mfa.MfaSecret;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "mfa_secrets")
public class MfaSecretEntity {

    @Id
    private UUID id;

    @Column(name = "user_id", nullable = false, unique = true)
    private UUID userId;

    @Column(name = "secret_cipher", nullable = false)
    private String secretCipher;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private MfaMethod method;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "confirmed_at")
    private Instant confirmedAt;

    protected MfaSecretEntity() {}

    public static MfaSecretEntity from(MfaSecret s) {
        MfaSecretEntity e = new MfaSecretEntity();
        e.id = s.id();
        e.userId = s.userId().value();
        e.secretCipher = s.secretCipher();
        e.method = s.method();
        e.createdAt = s.createdAt();
        e.confirmedAt = s.confirmedAt();
        return e;
    }

    public MfaSecret toDomain() {
        return new MfaSecret(id, UserId.of(userId), secretCipher, method, createdAt, confirmedAt);
    }
}
