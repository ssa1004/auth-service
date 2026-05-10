package com.example.auth.adapter.in.rest;

import com.example.auth.application.port.in.ListMySessionsUseCase;
import com.example.auth.application.port.in.RevokeSessionUseCase;
import com.example.auth.adapter.in.security.AuthenticatedUser;
import com.example.auth.adapter.in.security.ClientIpResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/me/sessions")
@RequiredArgsConstructor
@Tag(name = "session")
@SecurityRequirement(name = "bearerAuth")
public class SessionController {

    private final ListMySessionsUseCase listMySessionsUseCase;
    private final RevokeSessionUseCase revokeSessionUseCase;
    private final ClientIpResolver clientIpResolver;

    @Operation(
            summary = "내 세션 목록",
            description = "현재 사용자의 활성 refresh 토큰 (디바이스 / IP / 마지막 사용 시각).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "성공"),
            @ApiResponse(responseCode = "401", description = "Bearer JWT 누락 / 만료")
    })
    @GetMapping
    public ResponseEntity<List<SessionResponse>> list(AuthenticatedUser me) {
        return ResponseEntity.ok(
                listMySessionsUseCase.list(me.tenantId(), me.userId()).stream()
                        .map(SessionResponse::from)
                        .toList());
    }

    @Operation(
            summary = "내 세션 revoke",
            description = "특정 세션을 즉시 종료 (해당 refresh 토큰을 REVOKED 마킹).")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "성공"),
            @ApiResponse(responseCode = "401", description = "Bearer JWT 누락 / 만료"),
            @ApiResponse(responseCode = "403", description = "본인 세션이 아님 (OPA tenant/owner 정책 위반)")
    })
    @DeleteMapping("/{sessionId}")
    public ResponseEntity<Void> revoke(
            AuthenticatedUser me,
            @PathVariable UUID sessionId,
            HttpServletRequest http) {
        revokeSessionUseCase.revoke(new RevokeSessionUseCase.Command(
                me.tenantId(), me.userId(), sessionId, clientIpResolver.resolve(http)));
        return ResponseEntity.noContent().build();
    }
}
