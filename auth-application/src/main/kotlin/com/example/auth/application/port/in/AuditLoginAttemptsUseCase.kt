package com.example.auth.application.port.`in`

import com.example.auth.domain.audit.AuditEvent
import com.example.auth.domain.audit.AuditEventType
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId

/**
 * 다른 use case 가 audit 이벤트를 기록할 때 호출하는 inbound port.
 * 별도 use case 로 분리해 둔 이유: REST 운영 endpoint 에서도 audit 추가가 필요한
 * 시나리오가 있고, 외부 SIEM 으로 push 하는 변경이 자주 발생하므로 단일 진입점이 유리.
 */
interface AuditLoginAttemptsUseCase {

    fun record(
        tenantId: TenantId,
        userId: UserId?,
        type: AuditEventType,
        ipAddress: String?,
        userAgent: String?,
        payload: Map<String, String>?,
    ): AuditEvent
}
