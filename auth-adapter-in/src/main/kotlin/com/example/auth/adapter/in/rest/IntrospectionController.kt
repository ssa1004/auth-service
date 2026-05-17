package com.example.auth.adapter.`in`.rest

import com.example.auth.application.port.`in`.IntrospectTokenUseCase
import com.example.auth.application.port.`in`.IntrospectTokenUseCase.Result
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.media.Content
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

/**
 * RFC 7662 Token Introspection endpoint (ADR-0017).
 *
 * Resource Server 가 access / refresh 토큰의 유효성을 본 IdP 에 직접 묻기 위한 표준
 * endpoint. 응답 본문은 RFC 7662 §2.2 의 표준 필드 — `active`, `scope`,
 * `client_id`, `sub`, `exp`, `iat`, `token_type` 등.
 *
 * 본 endpoint 는 client_credentials grant 로 인증된 client 만 호출 가능합니다 — 외부에
 * 임의 토큰 introspect 를 노출하면 토큰 oracle 이 됩니다 (공격자가 훔친 토큰의 유효성을
 * 자유롭게 검증). Spring Security 의 HTTP Basic 인증으로 SecurityFilterChain 에서 검증.
 *
 * RFC 7662 §2.2 — token 형식이 잘못됐거나 알 수 없는 token 이면 정보 누설 없이
 * `{"active":false}` 만 반환.
 */
@RestController
@Tag(name = "oauth2")
@SecurityRequirement(name = "clientBasic")
class IntrospectionController(
    private val useCase: IntrospectTokenUseCase,
) {

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
        requestBody = io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            content = [
                Content(
                    mediaType = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                    schema = Schema(implementation = IntrospectFormSchema::class),
                ),
            ],
        ),
    )
    @ApiResponses(
        ApiResponse(
            responseCode = "200",
            description = "RFC 7662 §2.2 응답 — active=true 시 표준 + 커스텀 필드, false 시 active 만",
        ),
        ApiResponse(responseCode = "401", description = "client_credentials Basic 인증 실패"),
    )
    @PostMapping(value = ["/oauth2/introspect"], consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE])
    fun introspect(
        @Parameter(description = "검증할 access JWT 또는 refresh token (평문)", required = true)
        @RequestParam("token") token: String,
        @Parameter(description = "RFC 7662 §2.1 의 hint — access_token | refresh_token")
        @RequestParam(value = "token_type_hint", required = false) tokenTypeHint: String?,
        caller: Authentication?,
    ): ResponseEntity<Map<String, Any>> {
        val callerClient = caller?.name
        val result = useCase.introspect(
            IntrospectTokenUseCase.Command(token, tokenTypeHint, callerClient),
        )
        return ResponseEntity.ok(toRfc7662(result))
    }

    /**
     * Springdoc 가 form-urlencoded body 의 schema 를 추출할 때 사용하는 스키마 표현 record.
     * 본 record 는 직접 인스턴스화되지 않습니다 — schema 정의용.
     */
    @Suppress("unused")
    @Schema(name = "IntrospectForm", description = "RFC 7662 introspection request body")
    @JvmRecord
    data class IntrospectFormSchema(
        @field:Schema(description = "검증할 token", requiredMode = Schema.RequiredMode.REQUIRED)
        val token: String,
        @field:Schema(description = "access_token | refresh_token", example = "access_token")
        val token_type_hint: String?,
    )

    private companion object {

        /**
         * RFC 7662 §2.2 응답 직렬화. 표준 필드 이름 (snake_case) 으로 매핑.
         * active=false 면 다른 필드는 모두 생략 — 정보 누설 방지.
         */
        fun toRfc7662(r: Result): Map<String, Any> {
            val body = LinkedHashMap<String, Any>()
            body["active"] = r.active
            if (!r.active) return body

            r.scope?.let { body["scope"] = it }
            r.clientId?.let { body["client_id"] = it }
            r.username?.let { body["username"] = it }
            r.tokenType?.let { body["token_type"] = it }
            r.expiresAt?.let { body["exp"] = it.epochSecond }
            r.issuedAt?.let { body["iat"] = it.epochSecond }
            r.notBefore?.let { body["nbf"] = it.epochSecond }
            r.subject?.let { body["sub"] = it }
            r.tenantId?.let { body["tnt"] = it } // multi-tenant 컨텍스트 (커스텀)
            if (r.roles.isNotEmpty()) body["roles"] = r.roles
            r.issuer?.let { body["iss"] = it }
            r.jwtId?.let { body["jti"] = it }
            for ((key, value) in r.additional) {
                if (value != null) body.putIfAbsent(key, value)
            }
            return body
        }
    }
}
