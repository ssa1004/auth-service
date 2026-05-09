-- V2 — audit 이벤트의 SIEM sink (Kafka) outbox.
-- ADR-0012 — append-only audit 는 DB 에 박제되고, 같은 트랜잭션에서 outbox row 가
-- 만들어진다. 별도 worker 가 outbox 를 폴링하여 Kafka 로 publish + 성공 시 published_at
-- 를 박제 (at-least-once — consumer 측 dedup).

CREATE TABLE audit_event_outbox (
    id              UUID        PRIMARY KEY,
    -- 같은 audit_events.id 를 참조 — FK 는 안 걸어 유연 (audit 가 다른 sink 로 옮겨가도
    -- outbox 만 따로 관리 가능).
    audit_event_id  UUID        NOT NULL,
    -- 발행 대상 토픽. 본 단계는 'auth.audit' 한 종류지만, 다른 도메인 이벤트가 같은
    -- outbox 메커니즘을 쓰면 분기 가능.
    topic           TEXT        NOT NULL,
    -- 직렬화된 JSON payload (전체 이벤트 schema, 'occurredAt' 포함).
    payload_json    TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    -- 발행 완료 시각. NULL 이면 미발행 → worker 가 polling 대상.
    published_at    TIMESTAMPTZ,
    -- 발행 실패 누적 횟수. 임계값 (기본 5) 넘으면 dead letter 처리 후속.
    attempt_count   INT         NOT NULL DEFAULT 0,
    -- 마지막 실패 사유. NULL 이면 정상.
    last_error      TEXT
);

-- 미발행 outbox 만 빠르게 찾기 위한 partial index.
CREATE INDEX audit_event_outbox_unpublished_idx
    ON audit_event_outbox(created_at) WHERE published_at IS NULL;
