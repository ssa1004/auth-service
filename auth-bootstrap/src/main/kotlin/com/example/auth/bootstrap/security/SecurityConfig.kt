package com.example.auth.bootstrap.security

import com.example.auth.adapter.`in`.security.JwtPermissionsConverter
import com.example.auth.application.security.AuthProperties
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter

/**
 * Spring Authorization Server (issuer) + Resource Server (consumer) 두 흐름을 한 앱에서
 * 같이 운영합니다.
 *
 * chain order:
 * 1. order 1 — Spring Authorization Server endpoint (oauth2, .well-known)
 *    — Spring 이 제공하는 OAuth2AuthorizationServerConfiguration 으로 자동 구성
 * 2. order 2 — 운영 endpoint (api/v1/me, api/v1/admin) —
 *    Bearer JWT resource server 로 검증, [JwtPermissionsConverter] 로 authority 매핑
 * 3. order 3 — public endpoint (api/v1/auth, actuator) — anonymous
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
open class SecurityConfig {

    /**
     * RFC 7662 introspect / RFC 7009 revoke 는 본 IdP 의 자체 컨트롤러가 처리하므로 (ADR-0017,
     * ADR-0018), Spring Authorization Server 가 같은 path 에 등록한 기본 endpoint 보다
     * 먼저 매칭되어야 합니다. order 0 으로 분리하고, client_secret_basic 으로 호출 client 만
     * 받습니다 — 외부에 공개 시 token oracle 이 되어 위험.
     */
    @Bean
    @Order(0)
    open fun tokenAdminEndpointsSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .securityMatcher("/oauth2/introspect", "/oauth2/revoke")
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .headers(::applyBaselineHeaders)
            .authorizeHttpRequests { reg -> reg.anyRequest().authenticated() }
            .httpBasic(Customizer.withDefaults())
        return http.build()
    }

    @Bean
    @Order(1)
    open fun authServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        val asConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer()
        // OIDC 명시 활성화 — /.well-known/openid-configuration / /userinfo / /connect/register
        asConfigurer.oidc(Customizer.withDefaults())

        http
            .securityMatcher(asConfigurer.endpointsMatcher)
            .with(asConfigurer, Customizer.withDefaults())
            .authorizeHttpRequests { reg -> reg.anyRequest().authenticated() }
            .csrf { it.ignoringRequestMatchers(asConfigurer.endpointsMatcher) }
            .headers(::applyBaselineHeaders)
            .exceptionHandling { ex ->
                ex.authenticationEntryPoint { _, res, _ -> res.sendError(401) }
            }
            .oauth2ResourceServer { rs -> rs.jwt(Customizer.withDefaults()) }
        return http.build()
    }

    @Bean
    @Order(2)
    open fun protectedApiSecurityFilterChain(
        http: HttpSecurity,
        converter: JwtPermissionsConverter,
    ): SecurityFilterChain {
        http
            .securityMatcher("/api/v1/me/**", "/api/v1/admin/**")
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .headers(::applyBaselineHeaders)
            .authorizeHttpRequests { reg -> reg.anyRequest().authenticated() }
            .oauth2ResourceServer { rs -> rs.jwt { jwt -> jwt.jwtAuthenticationConverter(converter) } }
        return http.build()
    }

    @Bean
    @Order(3)
    open fun publicSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .headers(::applyBaselineHeaders)
            .authorizeHttpRequests { reg ->
                reg
                    .requestMatchers(
                        "/api/v1/auth/**", "/actuator/**", "/swagger-ui/**",
                        "/v3/api-docs/**", "/error", "/.well-known/**",
                    )
                    .permitAll()
                    .anyRequest().denyAll()
            }
        return http.build()
    }

    /**
     * 모든 chain 에 동일하게 적용되는 baseline 응답 헤더 (OWASP API8 — Security Misconfig).
     *
     * - HSTS — TLS 다운그레이드 차단. IdP 로의 첫 요청부터 항상 HTTPS 강제. 운영 ingress
     *   가 TLS 종단이지만 origin 응답도 HSTS 를 같이 내야 browser 가 long-lived 로 기억함.
     * - X-Content-Type-Options: nosniff — MIME sniff 으로 JSON 응답이 HTML 로 오인되어
     *   XSS 실행 surface 가 만들어지는 것을 차단.
     * - X-Frame-Options: DENY — IdP 응답을 다른 origin 이 iframe 안에 넣을 일 없음.
     *   clickjacking 방지.
     * - Referrer-Policy: no-referrer — auth flow 의 URL (예: login oauth2 code google 경로) 이
     *   Referer 헤더로 다른 사이트에 새지 않도록.
     * - Cache-Control: no-store — 토큰 / introspect 응답이 중간 프록시 / 브라우저에 캐시
     *   되지 않게.
     *
     * CORS 는 본 IdP 가 직접 처리하지 않습니다 — 호출자 (다른 service / SPA) 는 본 IdP 와
     * 같은 origin 에서 호출하거나 ingress / API gateway 에서 CORS 정책을 통합 관리합니다.
     * 잘못된 CORS 설정이 IdP 의 attack surface 가 되는 것을 피하기 위한 의도적 선택.
     */
    private fun applyBaselineHeaders(headers: HeadersConfigurer<HttpSecurity>) {
        headers
            .httpStrictTransportSecurity { hsts ->
                hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31_536_000L) // 1 year (HSTS preload 권장값)
            }
            .contentTypeOptions(Customizer.withDefaults())
            .frameOptions { frame -> frame.deny() }
            .referrerPolicy { rp -> rp.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER) }
            .cacheControl(Customizer.withDefaults())
    }

    @Bean
    open fun authorizationServerSettings(properties: AuthProperties): AuthorizationServerSettings =
        AuthorizationServerSettings.builder()
            .issuer(properties.jwtIssuer)
            .build()

    /**
     * Resource server 가 자기 자신이 발행한 JWT 를 검증하기 위한 디코더. 같은 JWKSource 를
     * 공유하므로 회전 즉시 새 키도 인식하며 HTTP fetch 가 일어나지 않습니다.
     */
    @Bean
    open fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
        val processor = DefaultJWTProcessor<SecurityContext>()
        processor.jwsKeySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)
        return NimbusJwtDecoder(processor)
    }
}
