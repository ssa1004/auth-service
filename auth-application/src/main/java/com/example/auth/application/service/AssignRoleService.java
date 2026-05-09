package com.example.auth.application.service;

import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.port.in.AssignRoleUseCase;
import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.out.RoleRepository;
import com.example.auth.application.port.out.UserRepository;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.role.Role;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AssignRoleService implements AssignRoleUseCase {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuditLoginAttemptsUseCase auditUseCase;

    @Override
    @Transactional
    public void assign(Command cmd) {
        // 대상 사용자 / role 모두 같은 테넌트에 속해야 함 — repository 가 강제.
        userRepository.findById(cmd.tenantId(), cmd.targetUserId())
                .orElseThrow(InvalidCredentialsException::new);
        Role role = roleRepository.findById(cmd.tenantId(), cmd.roleId())
                .orElseThrow(InvalidCredentialsException::new);

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
