package com.example.auth.bootstrap.oidc;

import com.example.auth.application.port.in.LinkOrCreateUserFromOidcUseCase;
import com.example.auth.application.port.in.LinkOrCreateUserFromOidcUseCase.Command;
import com.example.auth.domain.identity.ExternalProvider;
import com.example.auth.domain.user.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * Google OIDC consumer wiring (ADR-0013).
 *
 * <p>{@code spring.security.oauth2.client.registration.google.client-id} 가 채워져 있을
 * 때만 활성. 본 단계는 Google 만 wiring 하지만 같은 패턴으로 다른 vendor 확장.
 *
 * <p>OidcUserService 가 Google 의 userinfo endpoint 호출 후 받은 sub / email 을
 * {@link LinkOrCreateUserFromOidcUseCase} 로 넘겨 사용자 도메인 ({@link User}) 과 매핑.
 */
@Configuration
@ConditionalOnProperty(prefix = "spring.security.oauth2.client.registration.google", name = "client-id")
@RequiredArgsConstructor
@Slf4j
public class OidcLoginAdapterConfig {

    private final LinkOrCreateUserFromOidcUseCase linkOrCreateUseCase;

    /**
     * 본 단계는 single-tenant 가정 — 운영 multi-tenant 에서는 redirect URI path 또는
     * state 파라미터로 tenantSlug 를 전달받아야 한다.
     */
    @Value("${auth.oidc.default-tenant-slug:default}")
    private String defaultTenantSlug;

    @Bean
    public OidcUserService customOidcUserService() {
        OidcUserService delegate = new OidcUserService();
        return new OidcUserService() {
            @Override
            public OidcUser loadUser(OidcUserRequest userRequest) {
                OidcUser oidcUser = delegate.loadUser(userRequest);
                String sub = oidcUser.getSubject();
                String email = oidcUser.getEmail();

                User user = linkOrCreateUseCase.linkOrCreate(new Command(
                        defaultTenantSlug,
                        ExternalProvider.GOOGLE,
                        sub,
                        email));

                log.info("OIDC userinfo 매핑 완료 sub={} userId={} status={}",
                        sub, user.id().asString(), user.status());
                return oidcUser;
            }
        };
    }
}
