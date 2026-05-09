package com.example.auth.adapter.out.persistence.user;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.example.auth.domain.user.MfaStatus;
import com.example.auth.domain.user.User;
import com.example.auth.domain.user.UserStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "users", uniqueConstraints = @UniqueConstraint(
        name = "users_tenant_email_uq", columnNames = {"tenant_id", "email"}))
public class UserEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(nullable = false)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status;

    @Enumerated(EnumType.STRING)
    @Column(name = "mfa_status", nullable = false)
    private MfaStatus mfaStatus;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected UserEntity() {}

    public static UserEntity from(User u) {
        UserEntity e = new UserEntity();
        e.id = u.id().value();
        e.tenantId = u.tenantId().value();
        e.email = u.email();
        e.passwordHash = u.passwordHash();
        e.status = u.status();
        e.mfaStatus = u.mfaStatus();
        e.createdAt = u.createdAt();
        e.updatedAt = u.updatedAt();
        return e;
    }

    public User toDomain() {
        return new User(
                UserId.of(id), TenantId.of(tenantId), email, passwordHash,
                status, mfaStatus, createdAt, updatedAt);
    }

    public UUID getId() { return id; }
}
