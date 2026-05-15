package com.example.auth.domain.user

import com.example.auth.domain.common.EmailMasker
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import java.time.Instant
import java.util.Objects

/**
 * User aggregate root.
 *
 * 비밀번호 해시는 BCrypt 결과 (cost=12) 만 들어옵니다. 평문 비밀번호는 도메인 객체에
 * 절대 들어오지 않습니다 — application 의 PasswordHasher port 에서 해시한 결과를 받습니다.
 *
 * email 은 PII 이므로 toString / log 호출 시 [EmailMasker] 로 가려야 합니다.
 * 본 클래스는 toString 을 명시적으로 override 해서 평문이 새지 않도록 막습니다.
 *
 * 불변 객체이며 상태 천이는 새 인스턴스를 반환한다. id 기준 동일성 + email/passwordHash 를
 * 노출하지 않는 toString 을 위해 일반 class 로 두고 `@get:JvmName` 으로 Java record-style
 * accessor (`u.id()` 등) 호환을 유지한다.
 */
class User(
    @get:JvmName("id") val id: UserId,
    @get:JvmName("tenantId") val tenantId: TenantId,
    @get:JvmName("email") @field:NotBlank @field:Email val email: String,
    @get:JvmName("passwordHash") @field:NotBlank val passwordHash: String,
    @get:JvmName("status") val status: UserStatus,
    @get:JvmName("mfaStatus") val mfaStatus: MfaStatus,
    @get:JvmName("createdAt") val createdAt: Instant,
    @get:JvmName("updatedAt") val updatedAt: Instant,
) {

    init {
        require(email.isNotBlank()) { "email 은 비어있을 수 없습니다" }
        require(passwordHash.isNotBlank()) { "passwordHash 는 비어있을 수 없습니다" }
        // BCrypt 출력은 60자, 어떤 hashing 알고리즘이라도 평문 비밀번호 (보통 8~32자) 가
        // 잘못 흘러들어오는 사고를 방지하기 위해 최소 길이 가드.
        require(passwordHash.length >= 20) { "passwordHash 는 hash 결과여야 합니다 (평문 금지)" }
    }

    fun markVerified(now: Instant): User {
        if (status != UserStatus.PENDING_VERIFICATION) {
            return this
        }
        return User(id, tenantId, email, passwordHash, UserStatus.ACTIVE, mfaStatus, createdAt, now)
    }

    fun lock(now: Instant): User =
        User(id, tenantId, email, passwordHash, UserStatus.LOCKED, mfaStatus, createdAt, now)

    fun unlock(now: Instant): User {
        if (status != UserStatus.LOCKED) {
            return this
        }
        return User(id, tenantId, email, passwordHash, UserStatus.ACTIVE, mfaStatus, createdAt, now)
    }

    fun changePassword(newPasswordHash: String, now: Instant): User =
        User(id, tenantId, email, newPasswordHash, status, mfaStatus, createdAt, now)

    fun enableMfa(now: Instant): User =
        User(id, tenantId, email, passwordHash, status, MfaStatus.ENABLED, createdAt, now)

    fun markMfaPending(now: Instant): User =
        User(id, tenantId, email, passwordHash, status, MfaStatus.PENDING, createdAt, now)

    fun disableMfa(now: Instant): User =
        User(id, tenantId, email, passwordHash, status, MfaStatus.DISABLED, createdAt, now)

    fun canLogin(): Boolean =
        status == UserStatus.ACTIVE || status == UserStatus.PENDING_VERIFICATION

    fun requiresMfa(): Boolean = mfaStatus == MfaStatus.ENABLED

    /**
     * 평문 email / passwordHash 를 절대 노출하지 않는 toString. 디버거 / 로그 / audit 어디서
     * 호출되더라도 안전.
     */
    override fun toString(): String =
        "User{" +
            "id=${id.asString()}" +
            ", tenantId=${tenantId.asString()}" +
            ", email=${EmailMasker.mask(email)}" +
            ", status=$status" +
            ", mfaStatus=$mfaStatus" +
            "}"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is User) return false
        return id == other.id
    }

    override fun hashCode(): Int = Objects.hash(id)

    companion object {
        @JvmStatic
        fun register(
            tenantId: TenantId,
            email: String,
            passwordHash: String,
            now: Instant,
        ): User = User(
            UserId.newId(),
            tenantId,
            email.lowercase().trim(),
            passwordHash,
            UserStatus.PENDING_VERIFICATION,
            MfaStatus.DISABLED,
            now,
            now,
        )
    }
}
