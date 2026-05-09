package com.example.auth.application.service;

import com.example.auth.application.authz.PolicyDecisionRequest;
import com.example.auth.application.authz.PolicyDecisionResult;
import com.example.auth.application.authz.PolicyDecisionService;
import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.exception.PolicyDeniedException;
import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.in.RevokeSessionUseCase;
import com.example.auth.application.port.out.RefreshTokenRepository;
import com.example.auth.application.port.out.RoleRepository;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.role.Role;
import com.example.auth.domain.token.RefreshToken;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RevokeSessionService implements RevokeSessionUseCase {

    private final RefreshTokenRepository refreshTokenRepository;
    private final RoleRepository roleRepository;
    private final AuditLoginAttemptsUseCase auditUseCase;
    private final PolicyDecisionService policyDecisionService;
    private final Clock clock;

    @Override
    @Transactional
    public void revoke(Command cmd) {
        // 1) 대상 세션 lookup. 같은 사용자의 활성 세션만 노출하므로 다른 사용자 세션 시도는
        //    여기서 InvalidCredentials 로 떨어짐 (RBAC 1차 방어).
        RefreshToken target = refreshTokenRepository.findActiveByUser(cmd.tenantId(), cmd.userId())
                .stream()
                .filter(t -> t.id().equals(cmd.sessionId()))
                .findFirst()
                .orElseThrow(InvalidCredentialsException::new);

        // 2) ABAC 정책 평가 (ADR-0016). 같은 사용자라도 정책에 따라 추가 거부 가능
        //    (예: 회사 정책상 마지막 활성 세션은 admin 만 revoke 가능 등). 정책 변경은
        //    Rego 파일 수정만으로 즉시 반영.
        Set<String> actorRoles = roleRepository.findByUser(cmd.tenantId(), cmd.userId())
                .stream().map(Role::slug).collect(Collectors.toSet());
        Map<String, Object> ctx = new LinkedHashMap<>();
        if (cmd.ipAddress() != null) ctx.put("ip", cmd.ipAddress());
        PolicyDecisionRequest request = new PolicyDecisionRequest(
                new PolicyDecisionRequest.Subject(
                        cmd.tenantId(), cmd.userId(), actorRoles, Set.of(), Map.of()),
                "session.revoke",
                new PolicyDecisionRequest.Resource(
                        "session", cmd.tenantId(), target.userId(),
                        Map.of("sessionId", target.id().toString())),
                ctx);
        PolicyDecisionResult decision = policyDecisionService.evaluate("auth/session/revoke", request);
        if (!decision.allow()) {
            throw new PolicyDeniedException(decision.reasons());
        }

        refreshTokenRepository.save(target.markRevokedByUser(clock.instant()));
        auditUseCase.record(
                cmd.tenantId(), cmd.userId(), AuditEventType.SESSION_REVOKED_BY_USER,
                cmd.ipAddress(), null,
                Map.of("sessionId", cmd.sessionId().toString()));
    }
}
