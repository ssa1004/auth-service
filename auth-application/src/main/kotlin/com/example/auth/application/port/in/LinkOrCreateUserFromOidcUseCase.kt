package com.example.auth.application.port.`in`

import com.example.auth.domain.identity.ExternalProvider
import com.example.auth.domain.user.User

/**
 * OIDC IdP 의 callback 을 받아 사용자 도메인 [User] 와 매핑하는 use case (ADR-0013).
 *
 * 흐름 — 기존 매핑 → 같은 이메일 사용자 link → 자동 가입.
 */
interface LinkOrCreateUserFromOidcUseCase {

    fun linkOrCreate(cmd: Command): User

    @JvmRecord
    data class Command(
        val tenantSlug: String,
        val provider: ExternalProvider,
        val providerUserId: String,
        val email: String?,
    )
}
