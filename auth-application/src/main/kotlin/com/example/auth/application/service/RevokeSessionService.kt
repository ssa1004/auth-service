package com.example.auth.application.service

import com.example.auth.application.authz.PolicyDecisionRequest
import com.example.auth.application.authz.PolicyDecisionService
import com.example.auth.application.exception.InvalidCredentialsException
import com.example.auth.application.exception.PolicyDeniedException
import com.example.auth.application.port.`in`.AuditLoginAttemptsUseCase
import com.example.auth.application.port.`in`.RevokeSessionUseCase
import com.example.auth.application.port.out.RefreshTokenRepository
import com.example.auth.application.port.out.RoleRepository
import com.example.auth.domain.audit.AuditEventType
import com.example.auth.domain.token.RefreshToken
import java.time.Clock
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class RevokeSessionService(
    private val refreshTokenRepository: RefreshTokenRepository,
    private val roleRepository: RoleRepository,
    private val auditUseCase: AuditLoginAttemptsUseCase,
    private val policyDecisionService: PolicyDecisionService,
    private val clock: Clock,
) : RevokeSessionUseCase {

    @Transactional
    override fun revoke(cmd: RevokeSessionUseCase.Command) {
        // 1) 대상 세션 lookup. 같은 사용자의 활성 세션만 노출하므로 다른 사용자 세션 시도는
        //    여기서 InvalidCredentials 로 떨어짐 (RBAC 1차 방어).
        val target: RefreshToken = refreshTokenRepository.findActiveByUser(cmd.tenantId, cmd.userId)
            .firstOrNull { it.id == cmd.sessionId }
            ?: throw InvalidCredentialsException()

        // 2) ABAC 정책 평가 (ADR-0016). 같은 사용자라도 정책에 따라 추가 거부 가능
        //    (예: 회사 정책상 마지막 활성 세션은 admin 만 revoke 가능 등). 정책 변경은
        //    Rego 파일 수정만으로 즉시 반영.
        val actorRoles: Set<String> = roleRepository.findByUser(cmd.tenantId, cmd.userId)
            .map { it.slug }.toSet()
        val ctx = LinkedHashMap<String, Any?>()
        if (cmd.ipAddress != null) ctx["ip"] = cmd.ipAddress
        val request = PolicyDecisionRequest(
            PolicyDecisionRequest.Subject(
                cmd.tenantId, cmd.userId, actorRoles, emptySet(), emptyMap(),
            ),
            "session.revoke",
            PolicyDecisionRequest.Resource(
                "session", cmd.tenantId, target.userId,
                mapOf("sessionId" to target.id.toString()),
            ),
            ctx,
        )
        val decision = policyDecisionService.evaluate("auth/session/revoke", request)
        if (!decision.allow) {
            throw PolicyDeniedException(decision.reasons)
        }

        refreshTokenRepository.save(target.markRevokedByUser(clock.instant()))
        auditUseCase.record(
            cmd.tenantId, cmd.userId, AuditEventType.SESSION_REVOKED_BY_USER,
            cmd.ipAddress, null,
            mapOf("sessionId" to cmd.sessionId.toString()),
        )
    }
}
