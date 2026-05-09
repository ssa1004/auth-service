package com.example.auth.adapter.in.rest;

import com.example.auth.adapter.in.security.AuthenticatedUser;
import com.example.auth.application.port.in.AssignRoleUseCase;
import com.example.auth.domain.common.UserId;
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
public class AdminController {

    private final AssignRoleUseCase assignRoleUseCase;

    /**
     * 운영자가 사용자에 role 부여. 실제로는 {@code admin:write} permission 필요 — JWT
     * 검증 단계에서 강제됩니다 (resource server 별 method security).
     */
    @PostMapping("/users/{userId}/roles")
    @PreAuthorize("hasAuthority('PERMISSION_admin:write')")
    public ResponseEntity<Void> assignRole(
            AuthenticatedUser actor,
            @PathVariable UUID userId,
            @RequestBody @NotNull AssignRoleRequest req,
            HttpServletRequest http) {
        assignRoleUseCase.assign(new AssignRoleUseCase.Command(
                actor.tenantId(), UserId.of(userId), req.roleId(),
                actor.userId(), http.getRemoteAddr()));
        return ResponseEntity.noContent().build();
    }

    public record AssignRoleRequest(@NotNull UUID roleId) {
    }
}
