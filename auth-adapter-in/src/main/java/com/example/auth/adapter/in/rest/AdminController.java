package com.example.auth.adapter.in.rest;

import com.example.auth.adapter.in.security.AuthenticatedUser;
import com.example.auth.adapter.in.security.ClientIpResolver;
import com.example.auth.application.port.in.AssignRoleUseCase;
import com.example.auth.domain.common.UserId;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@Tag(name = "admin")
@SecurityRequirement(name = "bearerAuth")
public class AdminController {

    private final AssignRoleUseCase assignRoleUseCase;
    private final ClientIpResolver clientIpResolver;

    /**
     * 운영자가 사용자에 role 부여. 실제로는 {@code admin:write} permission 필요 — JWT
     * 검증 단계에서 강제됩니다 (resource server 별 method security).
     */
    @Operation(
            summary = "사용자에 role 부여",
            description = """
                    PERMISSION_admin:write 가 JWT 의 권한에 포함되어야 호출 가능. 추가로
                    OPA 의 auth/role/assign 정책이 cross-tenant / admin role escalation 을
                    검증합니다 (admin role 부여는 senior_admin 만, cross-tenant 는 global_admin 만).
                    """)
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "성공"),
            @ApiResponse(responseCode = "401", description = "Bearer JWT 누락 / 만료"),
            @ApiResponse(responseCode = "403", description = "PERMISSION_admin:write 부족 또는 OPA 정책 거부")
    })
    @PostMapping("/users/{userId}/roles")
    @PreAuthorize("hasAuthority('PERMISSION_admin:write')")
    public ResponseEntity<Void> assignRole(
            AuthenticatedUser actor,
            @PathVariable UUID userId,
            @RequestBody @NotNull AssignRoleRequest req,
            HttpServletRequest http) {
        assignRoleUseCase.assign(new AssignRoleUseCase.Command(
                actor.tenantId(), UserId.of(userId), req.roleId(),
                actor.userId(), clientIpResolver.resolve(http)));
        return ResponseEntity.noContent().build();
    }

    public record AssignRoleRequest(@NotNull UUID roleId) {
    }
}
