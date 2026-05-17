package com.example.auth.bootstrap.oidc

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.web.SecurityFilterChain

/**
 * Google OIDC oauth2Login filter chain (ADR-0013).
 *
 * Spring Security 의 `oauth2Login()` 이 자동으로 다음 endpoint 를 노출:
 * - `oauth2 authorization {registrationId}` — IdP 로 redirect
 * - `login oauth2 code {registrationId}` — IdP 의 callback
 *
 * `spring.security.oauth2.client.registration.google.client-id` 가 없으면 본
 * config 가 비활성 → 기본 SecurityConfig 의 chain 만 작동 (테스트 환경 영향 없음).
 *
 * order=0 으로 두어 기본 SecurityConfig 의 다른 chain 보다 먼저 매칭. matcher 가 oauth2
 * endpoint 만 잡으므로 다른 흐름 영향 없음.
 */
@Configuration
@ConditionalOnProperty(
    prefix = "spring.security.oauth2.client.registration.google",
    name = ["client-id"],
)
open class OidcLoginSecurityConfig {

    @Bean
    @Order(0)
    open fun oidcLoginFilterChain(
        http: HttpSecurity,
        customOidcUserService: OidcUserService,
    ): SecurityFilterChain {
        http
            .securityMatcher("/oauth2/authorization/**", "/login/oauth2/code/**")
            .csrf { it.disable() }
            .authorizeHttpRequests { reg -> reg.anyRequest().authenticated() }
            .oauth2Login { login ->
                login.userInfoEndpoint { ui -> ui.oidcUserService(customOidcUserService) }
            }
        return http.build()
    }
}
