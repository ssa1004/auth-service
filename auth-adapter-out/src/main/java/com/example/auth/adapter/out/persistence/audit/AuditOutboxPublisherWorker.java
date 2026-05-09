package com.example.auth.adapter.out.persistence.audit;

import com.example.auth.application.port.out.SiemEventPublisher;
import java.time.Clock;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * outbox row 를 폴링해서 {@link SiemEventPublisher} 로 발행하는 worker (ADR-0012).
 *
 * <p>at-least-once — publish 직후 클라이언트 / 네트워크 장애로 published_at 기록에
 * 실패하면 다음 사이클에 같은 row 가 재발행될 수 있습니다. consumer 측에서 eventId
 * (`payload.eventId`) 기반 dedup 이 필요합니다.
 *
 * <p>한 사이클당 BATCH_SIZE (50) 만 처리합니다. DB 부하와 SIEM 토폴로지 부담의 균형.
 * 실패 누적 MAX_ATTEMPTS (5) 이상은 일단 폴링에서 빠지고 dead-letter 로 분리하는 것이
 * 후속 작업 (운영 알람 / 수동 재처리).
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditOutboxPublisherWorker {

    private static final int BATCH_SIZE = 50;
    private static final int MAX_ATTEMPTS = 5;

    private final AuditEventOutboxJpaRepository outboxJpa;
    private final SiemEventPublisher publisher;
    private final Clock clock;

    /**
     * 2초 주기로 미발행 outbox 처리. 주기는 SIEM 으로 흘리는 SLA 와 균형 — 보안팀이
     * "대시보드에 1분 안에 보여야 한다" 면 충분하고, 저빈도 audit 라 부담도 적음.
     */
    @Scheduled(fixedDelayString = "${auth.audit.outbox-poll-interval:2000}")
    @Transactional
    public void publishPendingBatch() {
        List<AuditEventOutboxEntity> batch =
                outboxJpa.findUnpublished(MAX_ATTEMPTS, PageRequest.of(0, BATCH_SIZE));
        if (batch.isEmpty()) {
            return;
        }
        for (AuditEventOutboxEntity row : batch) {
            try {
                publisher.publish(row.getTopic(), row.getAuditEventId().toString(), row.getPayloadJson());
                row.markPublished(clock.instant());
            } catch (RuntimeException ex) {
                row.markFailed(ex.getClass().getSimpleName() + ": " + ex.getMessage());
                if (row.getAttemptCount() >= MAX_ATTEMPTS) {
                    log.error("audit outbox 발행 실패 임계값 초과 outboxId={} auditEventId={} attempts={}",
                            row.getId(), row.getAuditEventId(), row.getAttemptCount());
                } else {
                    log.warn("audit outbox 발행 실패 outboxId={} attempts={} reason={}",
                            row.getId(), row.getAttemptCount(), ex.getMessage());
                }
            }
        }
    }
}
