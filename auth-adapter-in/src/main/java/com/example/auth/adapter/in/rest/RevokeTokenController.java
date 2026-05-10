package com.example.auth.adapter.in.rest;

import com.example.auth.adapter.in.security.ClientIpResolver;
import com.example.auth.application.exception.PolicyDeniedException;
import com.example.auth.application.port.in.RevokeTokenByAdminUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "oauth2")
@SecurityRequirement(name = "clientBasic")
public class RevokeTokenController {

    private final RevokeTokenByAdminUseCase useCase;
    private final RegisteredClientRepository registeredClientRepository;
    private final ClientIpResolver clientIpResolver;

    @Operation(
            summary = "RFC 7009 Token Revocation (admin)",
            description = """
                    운영자 / 보안 콘솔이 사용자의 access JWT 또는 refresh token 을 강제 종료.
                    호출 client 가 token.revoke scope 를 가져야 OPA 의 auth/token/revoke 정책을
                    통과합니다 (일반 service client 는 거부).

                    RFC 7009 §2.2 — 알 수 없는 token / 만료된 token / 다른 client 의 token
                    모두 응답은 항상 200 (정보 누설 차단). 다만 권한 자체가 없는 호출은
                    §2.2.1 의 unauthorized_client 처럼 403 으로 거부.
                    """,
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(
                            mediaType = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                            schema = @Schema(implementation = RevokeFormSchema.class))))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "RFC 7009 §2.2 — 항상 200, body 비어있음"),
            @ApiResponse(responseCode = "401", description = "client_credentials Basic 인증 실패"),
            @ApiResponse(responseCode = "403", description = "token.revoke scope 미보유 (OPA 거부)")
    })
    @PostMapping(value = "/oauth2/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> revoke(
            @Parameter(description = "강제 종료할 access JWT 또는 refresh token (평문)", required = true)
            @RequestParam("token") String token,
            @Parameter(description = "RFC 7009 §2.1 의 hint — access_token | refresh_token")
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            Authentication caller,
            HttpServletRequest http) {
        String callerClient = caller != null ? caller.getName() : null;
        Set<String> scopes = resolveScopes(callerClient, caller);
        try {
            useCase.revoke(new RevokeTokenByAdminUseCase.Command(
                    token, tokenTypeHint, callerClient, scopes, clientIpResolver.resolve(http)));
            return ResponseEntity.ok().build();
        } catch (PolicyDeniedException ex) {
            // RFC 7009 의 200 응답 규칙은 *유효한 client* 가 알 수 없는 token 을 보낼 때만
            // 적용. 권한 자체가 없는 호출은 §2.2.1 의 unauthorized_client 처럼 거부.
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    /**
     * 호출 client 의 scope 집합을 결정합니다.
     *
     * <p>두 소스를 *합치지* 않고 우선순위로 선택합니다 — 합산은 권한 over-broad 위험이 있어
     * 잘못된 모델입니다 (예: grant flow 가 발급 scope 을 다운스코프했는데, RegisteredClient
     * 의 상한치까지 합쳐 OPA 에 전달하면 grant 의 의미가 무력화).
     *
     * <ol>
     *   <li>caller (Spring Security) 가 SCOPE_* authority 를 가지면 = OAuth2 grant 로 발급된
     *       access token 의 실제 scope. 이것이 exercised privilege 의 정확한 표현.</li>
     *   <li>그렇지 않으면 (HttpBasic 등 grant 비경유) RegisteredClient.getScopes() 를 fallback —
     *       client 의 capability 전체. Basic 인증은 grant 가 없어 capability = privilege.</li>
     * </ol>
     */
    private Set<String> resolveScopes(String clientId, Authentication caller) {
        Set<String> grantedScopes = extractScopesFromAuthorities(caller);
        if (!grantedScopes.isEmpty()) {
            return grantedScopes;
        }
        if (clientId == null) return Set.of();
        RegisteredClient rc = registeredClientRepository.findByClientId(clientId);
        if (rc == null || rc.getScopes() == null) return Set.of();
        return Set.copyOf(rc.getScopes());
    }

    private static Set<String> extractScopesFromAuthorities(Authentication caller) {
        if (caller == null) return Set.of();
        Set<String> scopes = new HashSet<>();
        for (GrantedAuthority a : caller.getAuthorities()) {
            if (a.getAuthority().startsWith("SCOPE_")) {
                scopes.add(a.getAuthority().substring("SCOPE_".length()));
            }
        }
        return scopes;
    }

    /**
     * Springdoc 가 form-urlencoded body 의 schema 를 추출할 때 사용하는 표현 record.
     * 본 record 는 직접 인스턴스화되지 않습니다 — schema 정의용.
     */
    @SuppressWarnings("unused")
    @Schema(name = "RevokeForm", description = "RFC 7009 revocation request body")
    public record RevokeFormSchema(
            @Schema(description = "강제 종료할 token", requiredMode = Schema.RequiredMode.REQUIRED)
            String token,
            @Schema(description = "access_token | refresh_token", example = "refresh_token")
            String token_type_hint) {
    }
}
