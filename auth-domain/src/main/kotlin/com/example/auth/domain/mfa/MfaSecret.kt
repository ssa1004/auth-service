package com.example.auth.domain.mfa

import com.example.auth.domain.common.UserId
import java.time.Instant
import java.util.UUID

/**
 * 사용자 1인당 최대 1개의 TOTP secret. enable 전까지는 PENDING 상태로 보관됩니다.
 *
 * 비밀 자료(=TOTP shared secret) 는 도메인 객체에 *암호화된 상태* 로만 들어옵니다 —
 * application 의 `MfaSecretCipher` port 에서 AES 암호화한 결과를 받습니다. 평문
 * secret 은 한 곳 (TOTP 검증 직전) 에서만 잠시 메모리에 존재하고 즉시 폐기됩니다.
 *
 * `@JvmRecord data class` — Java 호출자 (`s.id()` / `s.userId()` / `s.secretCipher()`
 * record-style accessor) 그대로 동작. 단 `toString` 은 secretCipher 노출 차단을 위해
 * 명시적으로 override 한다 (data class 자동 생성 toString 사용 금지).
 */
@JvmRecord
data class MfaSecret(
    val id: UUID,
    val userId: UserId,
    val secretCipher: String,
    val method: MfaMethod,
    val createdAt: Instant,
    val confirmedAt: Instant?,
) {

    init {
        require(secretCipher.isNotBlank()) { "secretCipher 는 비어있을 수 없습니다" }
        // base32 secret 은 통상 32자, AES 암호화 결과는 더 길어집니다. 평문 secret
        // (보통 길이 16) 이 잘못 들어오는 사고를 한 번 더 가드.
        require(secretCipher.length >= 16) { "secretCipher 는 암호화된 값이어야 합니다" }
    }

    fun confirm(now: Instant): MfaSecret =
        MfaSecret(id, userId, secretCipher, method, createdAt, now)

    fun isConfirmed(): Boolean = confirmedAt != null

    /** secretCipher 는 *완전 비공개*. toString 에도 노출하지 않습니다. */
    override fun toString(): String =
        "MfaSecret{userId=${userId.asString()}, method=$method, confirmed=${isConfirmed()}}"

    companion object {
        @JvmStatic
        fun enroll(userId: UserId, secretCipher: String, method: MfaMethod, now: Instant): MfaSecret =
            MfaSecret(UUID.randomUUID(), userId, secretCipher, method, now, null)
    }
}
