package com.example.auth.adapter.`in`.rest

import com.example.auth.adapter.`in`.security.ClientIpResolver
import com.example.auth.application.exception.PolicyDeniedException
import com.example.auth.application.port.`in`.RevokeTokenByAdminUseCase
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.media.Content
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

/**
 * RFC 7009 Token Revocation endpoint (ADR-0018).
 *
 * 운영자 / 보안 콘솔이 사용자의 access JWT 또는 refresh token 을 강제 종료하는 경로.
 * 호출 client 가 `token.revoke` scope 를 가져야 OPA 정책을 통과합니다.
 *
 * RFC 7009 §2.2 — 알 수 없는 token / 만료된 token / 다른 client 의 token 모두 응답은
 * 항상 200. 정보 누설 차단이 표준의 핵심.
 */
@RestController
@Tag(name = "oauth2")
@SecurityRequirement(name = "clientBasic")
class RevokeTokenController(
    private val useCase: RevokeTokenByAdminUseCase,
    private val registeredClientRepository: RegisteredClientRepository,
    private val clientIpResolver: ClientIpResolver,
) {

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
        requestBody = io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            content = [
                Content(
                    mediaType = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                    schema = Schema(implementation = RevokeFormSchema::class),
                ),
            ],
        ),
    )
    @ApiResponses(
        ApiResponse(responseCode = "200", description = "RFC 7009 §2.2 — 항상 200, body 비어있음"),
        ApiResponse(responseCode = "401", description = "client_credentials Basic 인증 실패"),
        ApiResponse(responseCode = "403", description = "token.revoke scope 미보유 (OPA 거부)"),
    )
    @PostMapping(value = ["/oauth2/revoke"], consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE])
    fun revoke(
        @Parameter(description = "강제 종료할 access JWT 또는 refresh token (평문)", required = true)
        @RequestParam("token") token: String,
        @Parameter(description = "RFC 7009 §2.1 의 hint — access_token | refresh_token")
        @RequestParam(value = "token_type_hint", required = false) tokenTypeHint: String?,
        caller: Authentication?,
        http: HttpServletRequest,
    ): ResponseEntity<Void> {
        val callerClient = caller?.name
        val scopes = resolveScopes(callerClient, caller)
        return try {
            useCase.revoke(
                RevokeTokenByAdminUseCase.Command(
                    token, tokenTypeHint, callerClient, scopes, clientIpResolver.resolve(http),
                ),
            )
            ResponseEntity.ok().build()
        } catch (ex: PolicyDeniedException) {
            // RFC 7009 의 200 응답 규칙은 *유효한 client* 가 알 수 없는 token 을 보낼 때만
            // 적용. 권한 자체가 없는 호출은 §2.2.1 의 unauthorized_client 처럼 거부.
            ResponseEntity.status(HttpStatus.FORBIDDEN).build()
        }
    }

    /**
     * 호출 client 의 scope 집합을 결정합니다.
     *
     * 두 소스를 *합치지* 않고 우선순위로 선택합니다 — 합산은 권한 over-broad 위험이 있어
     * 잘못된 모델입니다 (예: grant flow 가 발급 scope 을 다운스코프했는데, RegisteredClient
     * 의 상한치까지 합쳐 OPA 에 전달하면 grant 의 의미가 무력화).
     *
     * 1. caller (Spring Security) 가 SCOPE_* authority 를 가지면 = OAuth2 grant 로 발급된
     *    access token 의 실제 scope. 이것이 exercised privilege 의 정확한 표현.
     * 2. 그렇지 않으면 (HttpBasic 등 grant 비경유) RegisteredClient.getScopes() 를 fallback —
     *    client 의 capability 전체. Basic 인증은 grant 가 없어 capability = privilege.
     */
    private fun resolveScopes(clientId: String?, caller: Authentication?): Set<String> {
        val grantedScopes = extractScopesFromAuthorities(caller)
        if (grantedScopes.isNotEmpty()) {
            return grantedScopes
        }
        if (clientId == null) return emptySet()
        val rc = registeredClientRepository.findByClientId(clientId)
        val scopes = rc?.scopes ?: return emptySet()
        return java.util.Set.copyOf(scopes)
    }

    /**
     * Springdoc 가 form-urlencoded body 의 schema 를 추출할 때 사용하는 표현 record.
     * 본 record 는 직접 인스턴스화되지 않습니다 — schema 정의용.
     */
    @Suppress("unused")
    @Schema(name = "RevokeForm", description = "RFC 7009 revocation request body")
    @JvmRecord
    data class RevokeFormSchema(
        @field:Schema(description = "강제 종료할 token", requiredMode = Schema.RequiredMode.REQUIRED)
        val token: String,
        @field:Schema(description = "access_token | refresh_token", example = "refresh_token")
        val token_type_hint: String?,
    )

    private companion object {
        fun extractScopesFromAuthorities(caller: Authentication?): Set<String> {
            if (caller == null) return emptySet()
            val scopes = HashSet<String>()
            for (a in caller.authorities) {
                if (a.authority.startsWith("SCOPE_")) {
                    scopes.add(a.authority.substring("SCOPE_".length))
                }
            }
            return scopes
        }
    }
}
