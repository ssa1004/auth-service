package com.example.auth.bootstrap.security;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * RFC 7662 introspect / RFC 7009 revoke endpoint 가 client_secret_basic 로 호출될 때
 * 사용하는 인증 어댑터.
 *
 * <p>Spring Authorization Server 의 RegisteredClient 를 그대로 사용해 client 를 인식합니다.
 * client_secret 이 {@code {noop}} prefix 로 저장되어 있으면 평문 비교, 그 외는 등록된
 * {@link PasswordEncoder} 로 비교 (운영에서는 BCrypt 권장).
 */
@Configuration
public class RegisteredClientBasicAuthConfig {

    /** Spring Security 가 client_secret 비교에 사용하는 encoder. RegisteredClient 의 prefix
     *  ({noop}, {bcrypt}) 에 따라 분기되도록 delegating encoder 를 사용합니다. */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return org.springframework.security.crypto.factory.PasswordEncoderFactories
                .createDelegatingPasswordEncoder();
    }

    /**
     * Spring Security 의 표준 HttpBasic 흐름이 RegisteredClient 를 인식하도록 위임 어댑터.
     * client 만 처리하므로 ROLE 은 {@code ROLE_CLIENT} 하나만.
     */
    @Bean
    public UserDetailsService registeredClientAsUserDetailsService(
            RegisteredClientRepository registeredClientRepository) {
        return username -> {
            var client = registeredClientRepository.findByClientId(username);
            if (client == null) {
                throw new UsernameNotFoundException("client not found");
            }
            String secret = client.getClientSecret();
            if (secret == null) {
                throw new UsernameNotFoundException("client without secret");
            }
            return new User(client.getClientId(), secret,
                    List.of(new SimpleGrantedAuthority("ROLE_CLIENT")));
        };
    }
}
