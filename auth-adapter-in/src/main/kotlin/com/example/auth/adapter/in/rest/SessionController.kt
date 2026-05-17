package com.example.auth.adapter.`in`.rest

import com.example.auth.adapter.`in`.security.AuthenticatedUser
import com.example.auth.adapter.`in`.security.ClientIpResolver
import com.example.auth.application.port.`in`.ListMySessionsUseCase
import com.example.auth.application.port.`in`.RevokeSessionUseCase
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.servlet.http.HttpServletRequest
import java.util.UUID
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/me/sessions")
@Tag(name = "session")
@SecurityRequirement(name = "bearerAuth")
class SessionController(
    private val listMySessionsUseCase: ListMySessionsUseCase,
    private val revokeSessionUseCase: RevokeSessionUseCase,
    private val clientIpResolver: ClientIpResolver,
) {

    @Operation(
        summary = "내 세션 목록",
        description = "현재 사용자의 활성 refresh 토큰 (디바이스 / IP / 마지막 사용 시각).",
    )
    @ApiResponses(
        ApiResponse(responseCode = "200", description = "성공"),
        ApiResponse(responseCode = "401", description = "Bearer JWT 누락 / 만료"),
    )
    @GetMapping
    fun list(me: AuthenticatedUser): ResponseEntity<List<SessionResponse>> =
        ResponseEntity.ok(
            listMySessionsUseCase.list(me.tenantId, me.userId)
                .map { SessionResponse.from(it) },
        )

    @Operation(
        summary = "내 세션 revoke",
        description = "특정 세션을 즉시 종료 (해당 refresh 토큰을 REVOKED 마킹).",
    )
    @ApiResponses(
        ApiResponse(responseCode = "204", description = "성공"),
        ApiResponse(responseCode = "401", description = "Bearer JWT 누락 / 만료"),
        ApiResponse(responseCode = "403", description = "본인 세션이 아님 (OPA tenant/owner 정책 위반)"),
    )
    @DeleteMapping("/{sessionId}")
    fun revoke(
        me: AuthenticatedUser,
        @PathVariable sessionId: UUID,
        http: HttpServletRequest,
    ): ResponseEntity<Void> {
        revokeSessionUseCase.revoke(
            RevokeSessionUseCase.Command(
                me.tenantId, me.userId, sessionId, clientIpResolver.resolve(http),
            ),
        )
        return ResponseEntity.noContent().build()
    }
}
