package com.example.auth.application.service

import com.example.auth.application.authz.PolicyDecisionRequest
import com.example.auth.application.authz.PolicyDecisionService
import com.example.auth.application.exception.InvalidCredentialsException
import com.example.auth.application.exception.PolicyDeniedException
import com.example.auth.application.port.`in`.AssignRoleUseCase
import com.example.auth.application.port.`in`.AuditLoginAttemptsUseCase
import com.example.auth.application.port.out.RoleRepository
import com.example.auth.application.port.out.UserRepository
import com.example.auth.domain.audit.AuditEventType
import com.example.auth.domain.role.Role
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class AssignRoleService(
    private val userRepository: UserRepository,
    private val roleRepository: RoleRepository,
    private val auditUseCase: AuditLoginAttemptsUseCase,
    private val policyDecisionService: PolicyDecisionService,
) : AssignRoleUseCase {

    @Transactional
    override fun assign(cmd: AssignRoleUseCase.Command) {
        // 대상 사용자 / role 모두 같은 테넌트에 속해야 함 — repository 가 강제.
        val targetUser = userRepository.findById(cmd.tenantId, cmd.targetUserId)
            .orElseThrow { InvalidCredentialsException() }
        val role: Role = roleRepository.findById(cmd.tenantId, cmd.roleId)
            .orElseThrow { InvalidCredentialsException() }

        // RBAC (PreAuthorize 의 PERMISSION_admin:write) 통과 후 ABAC — 예: "admin role 부여는
        // senior-admin 보유자만" 같은 정책을 OPA 가 평가 (ADR-0016).
        val actorRoles: Set<String> = roleRepository.findByUser(cmd.tenantId, cmd.actorUserId)
            .map { it.slug }.toSet()
        val resourceAttrs = LinkedHashMap<String, Any?>()
        resourceAttrs["roleSlug"] = role.slug
        val ctx = LinkedHashMap<String, Any?>()
        if (cmd.ipAddress != null) ctx["ip"] = cmd.ipAddress
        val request = PolicyDecisionRequest(
            PolicyDecisionRequest.Subject(
                cmd.tenantId, cmd.actorUserId, actorRoles, emptySet(), emptyMap(),
            ),
            "role.assign",
            PolicyDecisionRequest.Resource(
                "role", cmd.tenantId, targetUser.id, resourceAttrs,
            ),
            ctx,
        )
        val decision = policyDecisionService.evaluate("auth/role/assign", request)
        if (!decision.allow) {
            throw PolicyDeniedException(decision.reasons)
        }

        roleRepository.assignToUser(cmd.tenantId, cmd.targetUserId, role.id)
        auditUseCase.record(
            cmd.tenantId, cmd.actorUserId, AuditEventType.ROLE_ASSIGNED,
            cmd.ipAddress, null,
            mapOf(
                "roleId" to role.id.toString(),
                "roleSlug" to role.slug,
                "targetUserId" to cmd.targetUserId.asString(),
            ),
        )
    }
}
