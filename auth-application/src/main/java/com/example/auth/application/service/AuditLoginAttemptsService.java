package com.example.auth.application.service;

import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.out.AuditLogRepository;
import com.example.auth.domain.audit.AuditEvent;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import java.time.Clock;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuditLoginAttemptsService implements AuditLoginAttemptsUseCase {

    private final AuditLogRepository auditLogRepository;
    private final Clock clock;

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuditEvent record(
            TenantId tenantId,
            UserId userId,
            AuditEventType type,
            String ipAddress,
            String userAgent,
            Map<String, String> payload) {
        // REQUIRES_NEW — 호출 트랜잭션이 rollback 돼도 audit 은 살아남아야 합니다 (보안 사후
        // 분석). 단, 호출자는 이 메서드가 실패해도 main 흐름을 막지 않도록 try/catch 권장.
        AuditEvent event = AuditEvent.of(
                tenantId, userId, type, ipAddress, userAgent, payload, clock.instant());
        return auditLogRepository.append(event);
    }
}
