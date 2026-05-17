package com.example.auth.bootstrap.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository

/**
 * RFC 7662 introspect / RFC 7009 revoke endpoint 가 client_secret_basic 로 호출될 때
 * 사용하는 인증 어댑터.
 *
 * Spring Authorization Server 의 RegisteredClient 를 그대로 사용해 client 를 인식합니다.
 * client_secret 이 `{noop}` prefix 로 저장되어 있으면 평문 비교, 그 외는 등록된
 * [PasswordEncoder] 로 비교 (운영에서는 BCrypt 권장).
 */
@Configuration
open class RegisteredClientBasicAuthConfig {

    /**
     * Spring Security 가 client_secret 비교에 사용하는 encoder. RegisteredClient 의 prefix
     * (`{noop}`, `{bcrypt}`) 에 따라 분기되도록 delegating encoder 를 사용합니다.
     */
    @Bean
    open fun passwordEncoder(): PasswordEncoder =
        PasswordEncoderFactories.createDelegatingPasswordEncoder()

    /**
     * Spring Security 의 표준 HttpBasic 흐름이 RegisteredClient 를 인식하도록 위임 어댑터.
     * client 만 처리하므로 ROLE 은 `ROLE_CLIENT` 하나만.
     */
    @Bean
    open fun registeredClientAsUserDetailsService(
        registeredClientRepository: RegisteredClientRepository,
    ): UserDetailsService = UserDetailsService { username ->
        val client = registeredClientRepository.findByClientId(username)
            ?: throw UsernameNotFoundException("client not found")
        val secret = client.clientSecret
            ?: throw UsernameNotFoundException("client without secret")
        User(client.clientId, secret, listOf(SimpleGrantedAuthority("ROLE_CLIENT")))
    }
}
