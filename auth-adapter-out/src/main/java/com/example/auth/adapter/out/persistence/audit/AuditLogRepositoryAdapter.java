package com.example.auth.adapter.out.persistence.audit;

import com.example.auth.application.port.out.AuditLogRepository;
import com.example.auth.domain.audit.AuditEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class AuditLogRepositoryAdapter implements AuditLogRepository {

    private final AuditEventJpaRepository jpa;

    @Override
    public AuditEvent append(AuditEvent event) {
        return jpa.save(AuditEventEntity.from(event)).toDomain();
    }
}
