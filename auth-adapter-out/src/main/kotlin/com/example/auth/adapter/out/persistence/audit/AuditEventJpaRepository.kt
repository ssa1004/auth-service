package com.example.auth.adapter.out.persistence.audit

import java.util.UUID
import org.springframework.data.jpa.repository.JpaRepository

interface AuditEventJpaRepository : JpaRepository<AuditEventEntity, UUID>
