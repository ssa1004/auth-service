package com.example.auth.adapter.in.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.auth.adapter.in.security.ClientIpResolver;
import com.example.auth.application.port.in.RevokeTokenByAdminUseCase;
import com.example.auth.application.security.AuthProperties;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * RevokeTokenController.resolveScopes 의 권한 over-broad 회귀 락다운.
 *
 * <p>이전 구현은 caller authorities + RegisteredClient.getScopes() 를 *합쳐서* OPA 에
 * 전달했음. 결과: HttpBasic 인증 (SCOPE_ authority 없음) 시 RegisteredClient 의 모든 scope
 * 이 자동으로 부여 — 한 client 가 token.revoke + token.introspect 를 동시에 등록하면
 * introspect-only 의도였던 호출도 token.revoke 권한을 갖게 됨 (capability 와 exercised
 * privilege 구분 실패).
 *
 * <p>현행 구현: caller 가 SCOPE_* 를 가지면 그것만 (= 발급된 scope). 없으면 RegisteredClient
 * fallback. 두 소스를 합치지 않음.
 */
class RevokeTokenControllerScopeResolutionTest {

    private RevokeTokenByAdminUseCase useCase;
    private RegisteredClientRepository repository;
    private RevokeTokenController controller;

    @BeforeEach
    void setUp() {
        useCase = mock(RevokeTokenByAdminUseCase.class);
        repository = mock(RegisteredClientRepository.class);
        ClientIpResolver ipResolver = new ClientIpResolver(AuthProperties.defaults());
        controller = new RevokeTokenController(useCase, repository, ipResolver);
    }

    @Test
    void caller_가_SCOPE_authority_를_가지면_그_scope_만_OPA_입력() {
        // 가상 시나리오: 미래에 OAuth2 access token 으로 호출 (현재 HttpBasic 만 지원)
        // — 발급된 scope 만 OPA 에 전달되어야 합니다.
        Authentication caller = authWithAuthorities("internal-admin",
                List.of("ROLE_CLIENT", "SCOPE_token.revoke"));
        // RegisteredClient 에는 token.revoke + token.introspect 둘 다 등록.
        when(repository.findByClientId("internal-admin"))
                .thenReturn(adminClientWithScopes("token.revoke", "token.introspect"));

        HttpServletRequest req = new MockHttpServletRequest();
        controller.revoke("token", "refresh_token", caller, req);

        ArgumentCaptor<RevokeTokenByAdminUseCase.Command> captor =
                ArgumentCaptor.forClass(RevokeTokenByAdminUseCase.Command.class);
        verify(useCase).revoke(captor.capture());
        // 핵심: SCOPE_token.revoke 만 들어가야 하고 token.introspect 는 *섞이지* 않아야 함.
        assertThat(captor.getValue().callerScopes()).containsExactly("token.revoke");
    }

    @Test
    void HttpBasic_caller_는_RegisteredClient_의_scope_으로_fallback() {
        // 현재 운영 시나리오 — HttpBasic 인증, ROLE_CLIENT 만 (SCOPE_ 없음).
        Authentication caller = authWithAuthorities("internal-admin", List.of("ROLE_CLIENT"));
        when(repository.findByClientId("internal-admin"))
                .thenReturn(adminClientWithScopes("token.revoke", "token.introspect"));

        HttpServletRequest req = new MockHttpServletRequest();
        controller.revoke("token", "refresh_token", caller, req);

        ArgumentCaptor<RevokeTokenByAdminUseCase.Command> captor =
                ArgumentCaptor.forClass(RevokeTokenByAdminUseCase.Command.class);
        verify(useCase).revoke(captor.capture());
        // Basic 인증은 grant 비경유 — capability = privilege. RegisteredClient 의 모든 scope.
        assertThat(captor.getValue().callerScopes())
                .containsExactlyInAnyOrder("token.revoke", "token.introspect");
    }

    @Test
    void caller_가_SCOPE_부족하면_RegisteredClient_capability_로_확장되지_않음() {
        // 보안 핵심: caller 에 SCOPE_token.introspect 만 있는데 RegisteredClient 는
        // token.revoke 도 등록한 경우 — 이전 합산 구현은 token.revoke 를 추가해 OPA 통과.
        // 현행은 SCOPE_token.introspect 만 전달 → OPA 가 정확히 거부.
        Authentication caller = authWithAuthorities("internal-admin",
                List.of("ROLE_CLIENT", "SCOPE_token.introspect"));
        when(repository.findByClientId("internal-admin"))
                .thenReturn(adminClientWithScopes("token.revoke", "token.introspect"));

        HttpServletRequest req = new MockHttpServletRequest();
        controller.revoke("token", "refresh_token", caller, req);

        ArgumentCaptor<RevokeTokenByAdminUseCase.Command> captor =
                ArgumentCaptor.forClass(RevokeTokenByAdminUseCase.Command.class);
        verify(useCase).revoke(captor.capture());
        assertThat(captor.getValue().callerScopes()).containsExactly("token.introspect");
        assertThat(captor.getValue().callerScopes()).doesNotContain("token.revoke");
    }

    @Test
    void clientId_가_repository_에_없으면_빈_scope() {
        Authentication caller = authWithAuthorities("ghost-client", List.of("ROLE_CLIENT"));
        when(repository.findByClientId("ghost-client")).thenReturn(null);

        HttpServletRequest req = new MockHttpServletRequest();
        controller.revoke("token", "refresh_token", caller, req);

        ArgumentCaptor<RevokeTokenByAdminUseCase.Command> captor =
                ArgumentCaptor.forClass(RevokeTokenByAdminUseCase.Command.class);
        verify(useCase).revoke(captor.capture());
        assertThat(captor.getValue().callerScopes()).isEmpty();
    }

    private static Authentication authWithAuthorities(String name, List<String> authorities) {
        return new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                name, "n/a",
                AuthorityUtils.createAuthorityList(authorities.toArray(new String[0])));
    }

    private static RegisteredClient adminClientWithScopes(String... scopes) {
        var builder = RegisteredClient.withId("admin-id")
                .clientId("internal-admin")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
        for (String s : scopes) builder.scope(s);
        return builder.build();
    }
}
