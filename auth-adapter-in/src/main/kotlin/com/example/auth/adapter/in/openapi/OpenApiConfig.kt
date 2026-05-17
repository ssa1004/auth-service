package com.example.auth.adapter.`in`.openapi

import com.example.auth.application.security.AuthProperties
import io.swagger.v3.oas.models.Components
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Contact
import io.swagger.v3.oas.models.info.Info
import io.swagger.v3.oas.models.info.License
import io.swagger.v3.oas.models.security.SecurityScheme
import io.swagger.v3.oas.models.servers.Server
import io.swagger.v3.oas.models.tags.Tag
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * OpenAPI 3 spec 의 info / 보안 스킴 / 서버 / 태그 정의.
 *
 * Springdoc 의 자동 추출만으로는 다음 두 가지가 누락됩니다:
 * - RFC 7662 introspect / RFC 7009 revoke 는 form-urlencoded body — 자동 모델
 *   추출이 빈약. 컨트롤러의 `@Operation` + `@Parameter` 로 보강.
 * - SecurityScheme — Bearer JWT 와 client_credentials Basic 두 종류. 본 bean 으로
 *   각각 등록하여 Swagger UI 의 "Authorize" 가 정확히 동작.
 *
 * swagger UI / api-docs 노출 자체는 application-{profile}.yml 의 `springdoc.*`
 * 와 SecurityConfig 의 publicSecurityFilterChain 에서 함께 통제 — production profile 은
 * disable 권장 (token oracle 위험은 없으나 endpoint 매핑 정보 노출 surface 축소).
 */
@Configuration
class OpenApiConfig {

    @Bean
    fun authServiceOpenApi(properties: AuthProperties): OpenAPI = OpenAPI()
        .info(info())
        .addServersItem(Server().url(properties.jwtIssuer).description("Configured issuer URL"))
        .components(components())
        .tags(
            listOf(
                Tag().name("auth").description("회원가입 / 로그인 / refresh / MFA 검증"),
                Tag().name("session").description("내 세션 목록 / revoke (자기 자신)"),
                Tag().name("admin").description("운영자 전용 endpoint (RBAC + ABAC)"),
                Tag().name("oauth2").description("RFC 7662 introspection / RFC 7009 revocation"),
            ),
        )

    private fun info(): Info = Info()
        .title("auth-service")
        .description(
            """
            OAuth2 / OIDC IdP — JWT 발행 + JWK rotation + refresh rotation +
            RBAC + ABAC (OPA) + MFA TOTP + audit. RFC 7662 / 7009 표준 endpoint
            포함. 자세한 설계 결정은 docs/adr 참조.

            보안 스킴:
            - bearerAuth: 자체 발행 access JWT. /api/v1/me/**, /api/v1/admin/** 호출 시.
            - clientBasic: client_credentials 의 client_id:client_secret. /oauth2/introspect,
              /oauth2/revoke 호출 시 — 외부에 임의 토큰 introspect 노출 차단.
            """.trimIndent(),
        )
        .version("0.1.0")
        .license(License().name("MIT").url("https://opensource.org/licenses/MIT"))
        .contact(Contact().name("auth-service maintainers"))

    private fun components(): Components = Components()
        .addSecuritySchemes(
            "bearerAuth",
            SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .description("자체 발행 access JWT — RS256, 15분 유효, JWK rotation 24h."),
        )
        .addSecuritySchemes(
            "clientBasic",
            SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("basic")
                .description("RFC 6749 client_credentials — Authorization: Basic base64(client_id:secret)"),
        )
}
