# ADR-0012: Audit log SIEM 아웃박스 (Kafka 발행)

## 상태
적용

## 배경
ADR-0008 에서 audit 를 DB append-only 로 보관합니다. 운영 사고가 났을 때 보안팀은 실시간
분석을 위해 SIEM (Splunk / Elastic / Datadog) 도구를 사용하므로, DB 에만 적재하고 SIEM
으로 못 흘려보내면 다음 문제가 생깁니다.

- 사고 인지가 늦어집니다 (DB 스캔은 운영팀의 수동 쿼리).
- 룰 기반 알람 (예: "5분 안에 같은 IP 에서 100회 LOGIN_FAILED") 을 SIEM 이 보지 못합니다.
- 컴플라이언스 (PCI-DSS / ISO 27001) 의 "tamper-resistant centralized logging" 요건 미흡.

직접 service 에서 Kafka 로 보내면 dual-write 문제가 발생합니다.

- DB 트랜잭션 commit 직후 Kafka publish 가 실패하면 SIEM 에 안 흐릅니다.
- Kafka publish 성공 후 트랜잭션이 rollback 되면 SIEM 에는 있고 DB 에는 없는 상태가
  됩니다.

## 결정
Outbox 패턴.

1. `AuditLogRepositoryAdapter.append()` — 같은 트랜잭션에서 두 row 를 INSERT:
   - `audit_events` (기존, append-only)
   - `audit_event_outbox` (신규, V2 마이그레이션)
2. `AuditOutboxPublisherWorker` — `@Scheduled(2s)` 폴링. 미발행 row 를 batch (50) 단위로
   `SiemEventPublisher.publish(topic, key, payloadJson)` 호출, 성공 시 `published_at` 기록.
3. 실패 시 `attempt_count` 증가 + `last_error` 기록. 5회 누적되면 폴링 대상에서 제외하고
   운영 알람 + 수동 dead-letter 처리 (후속).

at-least-once — publish 직후 published_at 기록에 실패하면 다음 사이클에 같은 row 가 재
발행될 수 있으므로 consumer 측에서 `eventId` 기반 dedup 이 필요합니다.

### Topic schema (`auth.audit`)
```json
{
  "eventId": "<uuid>",          // audit_events.id — consumer dedup 키
  "occurredAt": "ISO-8601",
  "tenantId": "<uuid>",
  "actor": "<userId or null>",  // 미인증 실패는 null
  "action": "LOGIN_SUCCEEDED|REFRESH_REUSE_DETECTED|...",
  "ip": "...",
  "userAgent": "...",
  "payload": { ... }            // 자유 형식. 평문 비밀번호 / 토큰 금지 (ADR-0008).
}
```

partition key 는 `eventId` (auditEventId) — consumer 측에서 같은 이벤트가 여러 파티션에
흩어지지 않게.

### `SiemEventPublisher` 인터페이스
- 기본 (dev/local) 구현: `LoggingSiemEventPublisher` — INFO 로그로 출력.
- 운영 구현: Spring Kafka `KafkaTemplate` 기반 (별도 wiring, 본 ADR 시점에는 mock).
  Kafka 라이브러리를 본 모듈에 강제 의존시키지 않기 위해 인터페이스로 추상화합니다.

## 결과
- audit 가 commit 되면 SIEM 도 결국 수신합니다 (at-least-once 보장).
- DB 와 Kafka 의 dual-write race 사고를 차단합니다.
- (단점) 발행 latency = 폴링 주기 (2s). 더 짧게 가려면 LISTEN/NOTIFY 또는 Debezium CDC
  도입을 고려할 수 있지만 본 시점에는 과합니다.

## 다시 검토할 시점
- audit 양이 batch 50 / 2초로 못 따라갈 때 → batch 크기 / 주기 / Debezium CDC.
- dead-letter 가 자주 쌓일 때 → SIEM 측 throttling / circuit breaker.
- 다른 도메인 이벤트도 SIEM 으로 보내야 할 때 → outbox 테이블을 공용 (`event_outbox`) 으로
  분리.
