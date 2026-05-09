package com.example.auth.adapter.in.rest;

import com.example.auth.application.port.in.ListMySessionsUseCase;
import com.example.auth.application.port.in.RevokeSessionUseCase;
import com.example.auth.adapter.in.security.AuthenticatedUser;
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
public class SessionController {

    private final ListMySessionsUseCase listMySessionsUseCase;
    private final RevokeSessionUseCase revokeSessionUseCase;

    @GetMapping
    public ResponseEntity<List<SessionResponse>> list(AuthenticatedUser me) {
        return ResponseEntity.ok(
                listMySessionsUseCase.list(me.tenantId(), me.userId()).stream()
                        .map(SessionResponse::from)
                        .toList());
    }

    @DeleteMapping("/{sessionId}")
    public ResponseEntity<Void> revoke(
            AuthenticatedUser me,
            @PathVariable UUID sessionId,
            HttpServletRequest http) {
        revokeSessionUseCase.revoke(new RevokeSessionUseCase.Command(
                me.tenantId(), me.userId(), sessionId, http.getRemoteAddr()));
        return ResponseEntity.noContent().build();
    }
}
