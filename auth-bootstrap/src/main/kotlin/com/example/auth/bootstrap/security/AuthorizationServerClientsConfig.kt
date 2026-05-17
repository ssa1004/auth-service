package com.example.auth.bootstrap.security

import java.util.UUID
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings

/**
 * Spring Authorization Server 의 client 등록.
 *
 * 현재는 in-memory + client_credentials grant 한 개. 운영에서는 DB 기반
 * `JdbcRegisteredClientRepository` 로 전환 + admin endpoint 로 client 등록 흐름
 * (후속).
 */
@Configuration
open class AuthorizationServerClientsConfig {

    @Bean
    open fun registeredClientRepository(
        @Value("\${auth.oauth2.demo-client-id:internal-service}") clientId: String,
        @Value("\${auth.oauth2.demo-client-secret:internal-service-secret-change-me}") clientSecret: String,
        @Value("\${auth.oauth2.admin-client-id:internal-admin}") adminClientId: String,
        @Value("\${auth.oauth2.admin-client-secret:internal-admin-secret-change-me}") adminClientSecret: String,
    ): RegisteredClientRepository {
        val demo = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            // client_secret 은 BCrypt 로 보관되어야 하지만 데모는 평문. 운영 전환 시
            // BCryptPasswordEncoder.encode(clientSecret) 으로 교체 필요.
            .clientSecret("{noop}$clientSecret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope(OidcScopes.OPENID)
            .scope("api.read")
            .scope("api.write")
            .clientSettings(ClientSettings.builder().requireProofKey(false).build())
            .tokenSettings(TokenSettings.builder().build())
            .build()
        // RFC 7009 admin revoke 전용 client (ADR-0018). token.revoke scope 가 OPA 정책의
        // 결정 attribute. 운영자 / 보안 콘솔이 본 client 로 강제 revoke 호출.
        val admin = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(adminClientId)
            .clientSecret("{noop}$adminClientSecret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("token.revoke")
            .scope("token.introspect")
            .clientSettings(ClientSettings.builder().requireProofKey(false).build())
            .tokenSettings(TokenSettings.builder().build())
            .build()
        return InMemoryRegisteredClientRepository(demo, admin)
    }
}
