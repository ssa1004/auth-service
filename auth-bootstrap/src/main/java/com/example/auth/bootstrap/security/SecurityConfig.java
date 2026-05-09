package com.example.auth.bootstrap.security;

import com.example.auth.adapter.in.security.JwtPermissionsConverter;
import com.example.auth.adapter.out.security.JwkSourceProvider;
import com.example.auth.application.security.AuthProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Authorization Server (issuer) + Resource Server (consumer) 두 흐름을 한 앱에서
 * 같이 운영합니다.
 *
 * <p>chain order:
 * <ol>
 *   <li>order 1 — Spring Authorization Server endpoint ({@code /oauth2/**}, {@code /.well-known/**})
 *       — Spring 이 제공하는 {@link OAuth2AuthorizationServerConfiguration} 으로 자동 구성</li>
 *   <li>order 2 — 운영 endpoint ({@code /api/v1/me/**}, {@code /api/v1/admin/**}) —
 *       Bearer JWT resource server 로 검증, {@link JwtPermissionsConverter} 로 authority 매핑</li>
 *   <li>order 3 — public endpoint ({@code /api/v1/auth/**}, {@code /actuator/**}) — anonymous</li>
 * </ol>
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http
                .exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, e) -> res.sendError(401)))
                .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain protectedApiSecurityFilterChain(
            HttpSecurity http,
            JwtPermissionsConverter converter) throws Exception {
        http
                .securityMatcher("/api/v1/me/**", "/api/v1/admin/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(reg -> reg.anyRequest().authenticated())
                .oauth2ResourceServer(rs -> rs.jwt(jwt -> jwt.jwtAuthenticationConverter(converter)));
        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain publicSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(reg -> reg
                        .requestMatchers("/api/v1/auth/**", "/actuator/**", "/swagger-ui/**",
                                "/v3/api-docs/**", "/error")
                        .permitAll()
                        .anyRequest().denyAll());
        return http.build();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(AuthProperties properties) {
        return AuthorizationServerSettings.builder()
                .issuer(properties.jwtIssuer())
                .build();
    }

    /**
     * Resource server 가 자기 자신이 발행한 JWT 를 검증하기 위한 디코더. 같은 JWKSource 를
     * 공유하므로 회전 즉시 새 키도 인식하며 HTTP fetch 가 일어나지 않습니다.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> selector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
        processor.setJWSKeySelector(selector);
        return new NimbusJwtDecoder(processor);
    }
}
