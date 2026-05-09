package com.example.auth.adapter.in.rest;

import com.example.auth.application.exception.PolicyDeniedException;
import com.example.auth.application.port.in.RevokeTokenByAdminUseCase;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashSet;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * RFC 7009 Token Revocation endpoint (ADR-0018).
 *
 * <p>운영자 / 보안 콘솔이 사용자의 access JWT 또는 refresh token 을 강제 종료하는 경로.
 * 호출 client 가 {@code token.revoke} scope 를 가져야 OPA 정책을 통과합니다.
 *
 * <p>RFC 7009 §2.2 — 알 수 없는 token / 만료된 token / 다른 client 의 token 모두 응답은
 * 항상 200. 정보 누설 차단이 표준의 핵심.
 */
@RestController
@RequiredArgsConstructor
public class RevokeTokenController {

    private final RevokeTokenByAdminUseCase useCase;
    private final RegisteredClientRepository registeredClientRepository;

    @PostMapping(value = "/oauth2/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> revoke(
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            Authentication caller,
            HttpServletRequest http) {
        String callerClient = caller != null ? caller.getName() : null;
        Set<String> scopes = resolveScopes(callerClient, caller);
        try {
            useCase.revoke(new RevokeTokenByAdminUseCase.Command(
                    token, tokenTypeHint, callerClient, scopes, http.getRemoteAddr()));
            return ResponseEntity.ok().build();
        } catch (PolicyDeniedException ex) {
            // RFC 7009 의 200 응답 규칙은 *유효한 client* 가 알 수 없는 token 을 보낼 때만
            // 적용. 권한 자체가 없는 호출은 §2.2.1 의 unauthorized_client 처럼 거부.
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    /**
     * 호출 client 의 scope 집합을 결정합니다. Spring AS 의 RegisteredClient 가 보유 scope
     * 목록을 가지고 있고, HttpBasic 인증된 client_id 로 lookup 합니다.
     */
    private Set<String> resolveScopes(String clientId, Authentication caller) {
        Set<String> scopes = new HashSet<>();
        if (caller != null) {
            for (GrantedAuthority a : caller.getAuthorities()) {
                if (a.getAuthority().startsWith("SCOPE_")) {
                    scopes.add(a.getAuthority().substring("SCOPE_".length()));
                }
            }
        }
        if (clientId != null) {
            RegisteredClient rc = registeredClientRepository.findByClientId(clientId);
            if (rc != null && rc.getScopes() != null) {
                scopes.addAll(rc.getScopes());
            }
        }
        return scopes;
    }
}
