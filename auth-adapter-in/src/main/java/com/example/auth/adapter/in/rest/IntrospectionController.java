package com.example.auth.adapter.in.rest;

import com.example.auth.application.port.in.IntrospectTokenUseCase;
import com.example.auth.application.port.in.IntrospectTokenUseCase.Result;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * RFC 7662 Token Introspection endpoint (ADR-0017).
 *
 * <p>Resource Server 가 access / refresh 토큰의 유효성을 본 IdP 에 직접 묻기 위한 표준
 * endpoint. 응답 본문은 RFC 7662 §2.2 의 표준 필드 — {@code active}, {@code scope},
 * {@code client_id}, {@code sub}, {@code exp}, {@code iat}, {@code token_type} 등.
 *
 * <p>본 endpoint 는 client_credentials grant 로 인증된 client 만 호출 가능합니다 — 외부에
 * 임의 토큰 introspect 를 노출하면 토큰 oracle 이 됩니다 (공격자가 훔친 토큰의 유효성을
 * 자유롭게 검증). Spring Security 의 HTTP Basic 인증으로 SecurityFilterChain 에서 검증.
 *
 * <p>RFC 7662 §2.2 — token 형식이 잘못됐거나 알 수 없는 token 이면 정보 누설 없이
 * {@code {"active":false}} 만 반환.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "oauth2")
@SecurityRequirement(name = "clientBasic")
public class IntrospectionController {

    private final IntrospectTokenUseCase useCase;

    @Operation(
            summary = "RFC 7662 Token Introspection",
            description = """
                    Resource Server 가 access / refresh 토큰의 유효성을 본 IdP 에 직접 묻는
                    표준 endpoint. 응답 본문은 RFC 7662 §2.2 의 표준 필드 — active, scope,
                    client_id, sub, exp, iat, token_type 등. token 형식이 잘못됐거나 알 수
                    없는 token 이면 정보 누설 없이 {"active":false} 만 반환.

                    호출자는 client_credentials grant 로 인증된 client 만 허용 — 외부에 임의
                    토큰 introspect 를 노출하면 token oracle 이 됩니다 (공격자가 훔친 토큰의
                    유효성을 자유롭게 검증).
                    """,
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(
                            mediaType = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                            schema = @Schema(implementation = IntrospectFormSchema.class))))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "RFC 7662 §2.2 응답 — active=true 시 표준 + 커스텀 필드, false 시 active 만"),
            @ApiResponse(responseCode = "401", description = "client_credentials Basic 인증 실패")
    })
    @PostMapping(value = "/oauth2/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> introspect(
            @Parameter(description = "검증할 access JWT 또는 refresh token (평문)", required = true)
            @RequestParam("token") String token,
            @Parameter(description = "RFC 7662 §2.1 의 hint — access_token | refresh_token")
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            Authentication caller) {
        String callerClient = caller != null ? caller.getName() : null;
        Result result = useCase.introspect(new IntrospectTokenUseCase.Command(
                token, tokenTypeHint, callerClient));
        return ResponseEntity.ok(toRfc7662(result));
    }

    /**
     * Springdoc 가 form-urlencoded body 의 schema 를 추출할 때 사용하는 스키마 표현 record.
     * 본 record 는 직접 인스턴스화되지 않습니다 — schema 정의용.
     */
    @SuppressWarnings("unused")
    @Schema(name = "IntrospectForm", description = "RFC 7662 introspection request body")
    public record IntrospectFormSchema(
            @Schema(description = "검증할 token", requiredMode = Schema.RequiredMode.REQUIRED)
            String token,
            @Schema(description = "access_token | refresh_token", example = "access_token")
            String token_type_hint) {
    }

    /**
     * RFC 7662 §2.2 응답 직렬화. 표준 필드 이름 (snake_case) 으로 매핑.
     * active=false 면 다른 필드는 모두 생략 — 정보 누설 방지.
     */
    private static Map<String, Object> toRfc7662(Result r) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("active", r.active());
        if (!r.active()) return body;

        if (r.scope() != null) body.put("scope", r.scope());
        if (r.clientId() != null) body.put("client_id", r.clientId());
        if (r.username() != null) body.put("username", r.username());
        if (r.tokenType() != null) body.put("token_type", r.tokenType());
        if (r.expiresAt() != null) body.put("exp", r.expiresAt().getEpochSecond());
        if (r.issuedAt() != null) body.put("iat", r.issuedAt().getEpochSecond());
        if (r.notBefore() != null) body.put("nbf", r.notBefore().getEpochSecond());
        if (r.subject() != null) body.put("sub", r.subject());
        if (r.tenantId() != null) body.put("tnt", r.tenantId()); // multi-tenant 컨텍스트 (커스텀)
        if (r.roles() != null && !r.roles().isEmpty()) body.put("roles", r.roles());
        if (r.issuer() != null) body.put("iss", r.issuer());
        if (r.jwtId() != null) body.put("jti", r.jwtId());
        if (r.additional() != null) {
            for (var e : r.additional().entrySet()) {
                body.putIfAbsent(e.getKey(), e.getValue());
            }
        }
        return body;
    }
}
