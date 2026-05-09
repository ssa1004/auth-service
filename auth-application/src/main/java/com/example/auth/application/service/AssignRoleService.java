package com.example.auth.application.service;

import com.example.auth.application.authz.PolicyDecisionRequest;
import com.example.auth.application.authz.PolicyDecisionResult;
import com.example.auth.application.authz.PolicyDecisionService;
import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.exception.PolicyDeniedException;
import com.example.auth.application.port.in.AssignRoleUseCase;
import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.out.RoleRepository;
import com.example.auth.application.port.out.UserRepository;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.role.Role;
import com.example.auth.domain.user.User;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AssignRoleService implements AssignRoleUseCase {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuditLoginAttemptsUseCase auditUseCase;
    private final PolicyDecisionService policyDecisionService;

    @Override
    @Transactional
    public void assign(Command cmd) {
        // 대상 사용자 / role 모두 같은 테넌트에 속해야 함 — repository 가 강제.
        User targetUser = userRepository.findById(cmd.tenantId(), cmd.targetUserId())
                .orElseThrow(InvalidCredentialsException::new);
        Role role = roleRepository.findById(cmd.tenantId(), cmd.roleId())
                .orElseThrow(InvalidCredentialsException::new);

        // RBAC (PreAuthorize 의 PERMISSION_admin:write) 통과 후 ABAC — 예: "admin role 부여는
        // senior-admin 보유자만" 같은 정책을 OPA 가 평가 (ADR-0016).
        Set<String> actorRoles = roleRepository.findByUser(cmd.tenantId(), cmd.actorUserId())
                .stream().map(Role::slug).collect(java.util.stream.Collectors.toSet());
        Map<String, Object> resourceAttrs = new LinkedHashMap<>();
        resourceAttrs.put("roleSlug", role.slug());
        Map<String, Object> ctx = new LinkedHashMap<>();
        if (cmd.ipAddress() != null) ctx.put("ip", cmd.ipAddress());
        PolicyDecisionRequest request = new PolicyDecisionRequest(
                new PolicyDecisionRequest.Subject(
                        cmd.tenantId(), cmd.actorUserId(), actorRoles, Set.of(), Map.of()),
                "role.assign",
                new PolicyDecisionRequest.Resource(
                        "role", cmd.tenantId(), targetUser.id(), resourceAttrs),
                ctx);
        PolicyDecisionResult decision = policyDecisionService.evaluate("auth/role/assign", request);
        if (!decision.allow()) {
            throw new PolicyDeniedException(decision.reasons());
        }

        roleRepository.assignToUser(cmd.tenantId(), cmd.targetUserId(), role.id());
        auditUseCase.record(
                cmd.tenantId(), cmd.actorUserId(), AuditEventType.ROLE_ASSIGNED,
                cmd.ipAddress(), null,
                Map.of(
                        "roleId", role.id().toString(),
                        "roleSlug", role.slug(),
                        "targetUserId", cmd.targetUserId().asString()));
    }
}
