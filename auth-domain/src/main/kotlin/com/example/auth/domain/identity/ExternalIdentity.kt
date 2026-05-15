package com.example.auth.domain.identity

import com.example.auth.domain.common.UserId
import java.time.Instant
import java.util.UUID

/**
 * 외부 IdP (Google / Microsoft / GitHub OIDC) 로 로그인한 사용자의 매핑 (ADR-0013).
 *
 * 같은 사용자가 여러 vendor 로 로그인할 수 있으므로 하나의 [UserId] 에 여러 row 가
 * 매달릴 수 있습니다. 단 `(provider, providerUserId)` 는 globally unique — 같은
 * Google 계정이 두 사용자에 매달리는 케이스 차단.
 *
 * `@JvmRecord data class` — Java 호출자 (`i.id()` / `i.userId()` / `i.provider()`
 * record-style accessor) 그대로 동작.
 */
@JvmRecord
data class ExternalIdentity(
    val id: UUID,
    val userId: UserId,
    val provider: ExternalProvider,
    /** IdP 측 user 의 sub. Google: numeric ID. Microsoft: oid. */
    val providerUserId: String,
    /** 가입 시점 IdP 가 알려준 이메일 — 추적용. 매핑 자체는 providerUserId 가 진실. */
    val emailAtLink: String?,
    val linkedAt: Instant,
    val lastLoginAt: Instant?,
) {

    init {
        require(providerUserId.isNotBlank()) { "providerUserId 는 비어있을 수 없습니다" }
    }

    fun touchLogin(now: Instant): ExternalIdentity =
        ExternalIdentity(id, userId, provider, providerUserId, emailAtLink, linkedAt, now)

    companion object {
        @JvmStatic
        fun link(
            userId: UserId,
            provider: ExternalProvider,
            providerUserId: String,
            emailAtLink: String?,
            now: Instant,
        ): ExternalIdentity = ExternalIdentity(
            UUID.randomUUID(), userId, provider, providerUserId, emailAtLink, now, now,
        )
    }
}
