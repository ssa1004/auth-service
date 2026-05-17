package com.example.auth.bootstrap.oidc

import com.example.auth.application.port.`in`.LinkOrCreateUserFromOidcUseCase
import com.example.auth.application.port.`in`.LinkOrCreateUserFromOidcUseCase.Command
import com.example.auth.domain.identity.ExternalProvider
import com.example.auth.domain.user.User
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.core.oidc.user.OidcUser

/**
 * Google OIDC consumer wiring (ADR-0013).
 *
 * `spring.security.oauth2.client.registration.google.client-id` 가 채워져 있을
 * 때만 활성. 본 단계는 Google 만 wiring 하지만 같은 패턴으로 다른 vendor 확장.
 *
 * OidcUserService 가 Google 의 userinfo endpoint 호출 후 받은 sub / email 을
 * [LinkOrCreateUserFromOidcUseCase] 로 넘겨 사용자 도메인 ([User]) 과 매핑.
 */
@Configuration
@ConditionalOnProperty(
    prefix = "spring.security.oauth2.client.registration.google",
    name = ["client-id"],
)
open class OidcLoginAdapterConfig(
    private val linkOrCreateUseCase: LinkOrCreateUserFromOidcUseCase,
) {

    /**
     * 본 단계는 single-tenant 가정 — 운영 multi-tenant 에서는 redirect URI path 또는
     * state 파라미터로 tenantSlug 를 전달받아야 한다.
     */
    @Value("\${auth.oidc.default-tenant-slug:default}")
    private lateinit var defaultTenantSlug: String

    @Bean
    open fun customOidcUserService(): OidcUserService {
        val delegate = OidcUserService()
        return object : OidcUserService() {
            override fun loadUser(userRequest: OidcUserRequest): OidcUser {
                val oidcUser = delegate.loadUser(userRequest)
                val sub = oidcUser.subject
                val email = oidcUser.email

                val user = linkOrCreateUseCase.linkOrCreate(
                    Command(defaultTenantSlug, ExternalProvider.GOOGLE, sub, email),
                )

                log.info(
                    "OIDC userinfo 매핑 완료 sub={} userId={} status={}",
                    sub, user.id.asString(), user.status,
                )
                return oidcUser
            }
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(OidcLoginAdapterConfig::class.java)
    }
}
