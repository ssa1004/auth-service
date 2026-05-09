package com.example.auth.adapter.out.persistence.audit;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditEventOutboxJpaRepository extends JpaRepository<AuditEventOutboxEntity, UUID> {

    /**
     * 미발행 row 를 오래된 순으로 N개 조회 — worker 가 batch 단위로 가져가 발행.
     *
     * <p>created_at 기준 ASC — 오래된 이벤트가 먼저 SIEM 에 도달.
     * attempt_count 임계값 이상은 dead letter 로 분리할 후속 작업 대상이라 일단 같이 가져옴.
     */
    @Query("SELECT o FROM AuditEventOutboxEntity o WHERE o.publishedAt IS NULL "
            + "AND o.attemptCount < :maxAttempts ORDER BY o.createdAt ASC")
    List<AuditEventOutboxEntity> findUnpublished(
            @Param("maxAttempts") int maxAttempts, PageRequest pageRequest);

    /** 발행 완료 N일 지난 row 정리 (운영 housekeeping 후속). */
    long deleteByPublishedAtBefore(Instant threshold);
}
