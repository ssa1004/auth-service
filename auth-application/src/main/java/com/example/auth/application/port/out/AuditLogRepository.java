package com.example.auth.application.port.out;

import com.example.auth.domain.audit.AuditEvent;

/**
 * append-only. 의도적으로 update / delete 메서드를 두지 않습니다 (ADR-0008).
 */
public interface AuditLogRepository {

    AuditEvent append(AuditEvent event);
}
