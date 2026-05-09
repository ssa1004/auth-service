package com.example.auth.adapter.in.rest;

import com.example.auth.application.port.in.IntrospectTokenUseCase;
import com.example.auth.application.port.in.IntrospectTokenUseCase.Result;
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
public class IntrospectionController {

    private final IntrospectTokenUseCase useCase;

    @PostMapping(value = "/oauth2/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> introspect(
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            Authentication caller) {
        String callerClient = caller != null ? caller.getName() : null;
        Result result = useCase.introspect(new IntrospectTokenUseCase.Command(
                token, tokenTypeHint, callerClient));
        return ResponseEntity.ok(toRfc7662(result));
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
