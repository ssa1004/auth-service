package com.example.auth.domain.user;

import com.example.auth.domain.common.EmailMasker;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.Objects;

/**
 * User aggregate root.
 *
 * <p>비밀번호 해시는 BCrypt 결과 (cost=12) 만 들어옵니다. 평문 비밀번호는 도메인 객체에
 * 절대 들어오지 않습니다 — application 의 PasswordHasher port 에서 해시한 결과를 받습니다.
 *
 * <p>email 은 PII 이므로 toString / log 호출 시 {@link EmailMasker} 로 가려야 합니다.
 * 이 record 는 일부러 toString 을 override 해서 평문 노출을 막습니다.
 */
public final class User {

    private final UserId id;
    private final TenantId tenantId;
    private final String email;
    private final String passwordHash;
    private final UserStatus status;
    private final MfaStatus mfaStatus;
    private final Instant createdAt;
    private final Instant updatedAt;

    public User(
            UserId id,
            TenantId tenantId,
            @NotBlank @Email String email,
            @NotBlank String passwordHash,
            UserStatus status,
            MfaStatus mfaStatus,
            Instant createdAt,
            Instant updatedAt) {
        this.id = Objects.requireNonNull(id, "user id 는 null 일 수 없습니다");
        this.tenantId = Objects.requireNonNull(tenantId, "tenantId 는 null 일 수 없습니다");
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email 은 비어있을 수 없습니다");
        }
        if (passwordHash == null || passwordHash.isBlank()) {
            throw new IllegalArgumentException("passwordHash 는 비어있을 수 없습니다");
        }
        if (passwordHash.length() < 20) {
            // BCrypt 출력은 60자, 어떤 hashing 알고리즘이라도 평문 비밀번호 (보통 8~32자) 가
            // 잘못 흘러들어오는 사고를 방지하기 위해 최소 길이 가드.
            throw new IllegalArgumentException("passwordHash 는 hash 결과여야 합니다 (평문 금지)");
        }
        this.email = email;
        this.passwordHash = passwordHash;
        this.status = Objects.requireNonNull(status);
        this.mfaStatus = Objects.requireNonNull(mfaStatus);
        this.createdAt = Objects.requireNonNull(createdAt);
        this.updatedAt = Objects.requireNonNull(updatedAt);
    }

    public static User register(
            TenantId tenantId,
            String email,
            String passwordHash,
            Instant now) {
        return new User(
                UserId.newId(),
                tenantId,
                email.toLowerCase().trim(),
                passwordHash,
                UserStatus.PENDING_VERIFICATION,
                MfaStatus.DISABLED,
                now,
                now);
    }

    public User markVerified(Instant now) {
        if (status != UserStatus.PENDING_VERIFICATION) {
            return this;
        }
        return new User(id, tenantId, email, passwordHash, UserStatus.ACTIVE, mfaStatus, createdAt, now);
    }

    public User lock(Instant now) {
        return new User(id, tenantId, email, passwordHash, UserStatus.LOCKED, mfaStatus, createdAt, now);
    }

    public User unlock(Instant now) {
        if (status != UserStatus.LOCKED) {
            return this;
        }
        return new User(id, tenantId, email, passwordHash, UserStatus.ACTIVE, mfaStatus, createdAt, now);
    }

    public User changePassword(String newPasswordHash, Instant now) {
        return new User(id, tenantId, email, newPasswordHash, status, mfaStatus, createdAt, now);
    }

    public User enableMfa(Instant now) {
        return new User(id, tenantId, email, passwordHash, status, MfaStatus.ENABLED, createdAt, now);
    }

    public User markMfaPending(Instant now) {
        return new User(id, tenantId, email, passwordHash, status, MfaStatus.PENDING, createdAt, now);
    }

    public User disableMfa(Instant now) {
        return new User(id, tenantId, email, passwordHash, status, MfaStatus.DISABLED, createdAt, now);
    }

    public boolean canLogin() {
        return status == UserStatus.ACTIVE || status == UserStatus.PENDING_VERIFICATION;
    }

    public boolean requiresMfa() {
        return mfaStatus == MfaStatus.ENABLED;
    }

    public UserId id() {
        return id;
    }

    public TenantId tenantId() {
        return tenantId;
    }

    public String email() {
        return email;
    }

    public String passwordHash() {
        return passwordHash;
    }

    public UserStatus status() {
        return status;
    }

    public MfaStatus mfaStatus() {
        return mfaStatus;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public Instant updatedAt() {
        return updatedAt;
    }

    /**
     * 평문 email / passwordHash 를 절대 노출하지 않는 toString. 디버거 / 로그 / audit 어디서
     * 호출되더라도 안전.
     */
    @Override
    public String toString() {
        return "User{"
                + "id=" + id.asString()
                + ", tenantId=" + tenantId.asString()
                + ", email=" + EmailMasker.mask(email)
                + ", status=" + status
                + ", mfaStatus=" + mfaStatus
                + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User other)) return false;
        return Objects.equals(id, other.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
