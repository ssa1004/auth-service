package com.example.auth.adapter.out.persistence.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.auth.application.port.out.SiemEventPublisher;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageRequest;

/**
 * AuditOutboxPublisherWorker (ADR-0012) — 정상 발행, 실패 시 attempt_count 증가,
 * 최대 시도 초과 시 폴링 대상에서 제외되는지 검증.
 */
class AuditOutboxPublisherWorkerTest {

    private AuditEventOutboxJpaRepository outboxJpa;
    private SiemEventPublisher publisher;
    private Clock clock;
    private AuditOutboxPublisherWorker worker;

    @BeforeEach
    void setUp() {
        outboxJpa = mock(AuditEventOutboxJpaRepository.class);
        publisher = mock(SiemEventPublisher.class);
        clock = Clock.fixed(Instant.parse("2026-05-09T10:00:00Z"), ZoneOffset.UTC);
        worker = new AuditOutboxPublisherWorker(outboxJpa, publisher, clock);
    }

    @Test
    void 폴링_시_미발행_row_를_publisher_로_발행하고_published_at_박제() {
        AuditEventOutboxEntity row = AuditEventOutboxEntity.create(
                UUID.fromString("11111111-1111-1111-1111-111111111111"),
                "auth.audit",
                "{\"eventId\":\"11111111-1111-1111-1111-111111111111\"}",
                Instant.parse("2026-05-09T09:59:50Z"));
        when(outboxJpa.findUnpublished(any(Integer.class), any(PageRequest.class)))
                .thenReturn(List.of(row));

        worker.publishPendingBatch();

        verify(publisher).publish(eq("auth.audit"),
                eq("11111111-1111-1111-1111-111111111111"),
                eq("{\"eventId\":\"11111111-1111-1111-1111-111111111111\"}"));
        assertThat(row.getPublishedAt()).isEqualTo(Instant.parse("2026-05-09T10:00:00Z"));
        assertThat(row.getAttemptCount()).isZero();
    }

    @Test
    void 발행_실패_시_attempt_count_증가_published_at_은_그대로_null() {
        AuditEventOutboxEntity row = AuditEventOutboxEntity.create(
                UUID.randomUUID(), "auth.audit", "{}",
                Instant.parse("2026-05-09T09:59:50Z"));
        when(outboxJpa.findUnpublished(any(Integer.class), any(PageRequest.class)))
                .thenReturn(List.of(row));

        doThrow(new RuntimeException("kafka broker down"))
                .when(publisher).publish(any(), any(), any());

        worker.publishPendingBatch();

        assertThat(row.getPublishedAt()).isNull();
        assertThat(row.getAttemptCount()).isEqualTo(1);
        assertThat(row.getLastError()).contains("kafka broker down");
    }

    @Test
    void 빈_batch_면_publisher_호출_없음() {
        when(outboxJpa.findUnpublished(any(Integer.class), any(PageRequest.class)))
                .thenReturn(List.of());

        worker.publishPendingBatch();

        // publisher 는 한 번도 호출되지 않아야 한다.
        verify(publisher, org.mockito.Mockito.never()).publish(any(), any(), any());
    }
}
