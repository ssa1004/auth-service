package com.example.auth.application.service

import com.example.auth.application.port.`in`.AuditLoginAttemptsUseCase
import com.example.auth.application.port.out.AuditLogRepository
import com.example.auth.domain.audit.AuditEvent
import com.example.auth.domain.audit.AuditEventType
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import java.time.Clock
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Propagation
import org.springframework.transaction.annotation.Transactional

@Service
class AuditLoginAttemptsService(
    private val auditLogRepository: AuditLogRepository,
    private val clock: Clock,
) : AuditLoginAttemptsUseCase {

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    override fun record(
        tenantId: TenantId,
        userId: UserId?,
        type: AuditEventType,
        ipAddress: String?,
        userAgent: String?,
        payload: Map<String, String>?,
    ): AuditEvent {
        // REQUIRES_NEW — 호출 트랜잭션이 rollback 돼도 audit 은 살아남아야 합니다 (보안 사후
        // 분석). 단, 호출자는 이 메서드가 실패해도 main 흐름을 막지 않도록 try/catch 권장.
        val event = AuditEvent.of(
            tenantId, userId, type, ipAddress, userAgent, payload, clock.instant(),
        )
        return auditLogRepository.append(event)
    }
}
