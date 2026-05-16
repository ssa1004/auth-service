package com.example.auth.application.port.out

import com.example.auth.domain.identity.ExternalIdentity
import com.example.auth.domain.identity.ExternalProvider
import java.util.Optional

/**
 * 외부 IdP (Google OIDC) 매핑 저장소 (ADR-0013).
 */
interface ExternalIdentityRepository {

    /**
     * (provider, providerUserId) 로 기존 매핑 조회. 같은 IdP 계정이 두 사용자에 매달리지
     * 않도록 (provider, providerUserId) 가 globally unique.
     */
    fun findByProviderSubject(provider: ExternalProvider, providerUserId: String): Optional<ExternalIdentity>

    fun save(identity: ExternalIdentity): ExternalIdentity
}
