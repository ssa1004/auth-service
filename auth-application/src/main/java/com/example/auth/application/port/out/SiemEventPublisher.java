package com.example.auth.application.port.out;

/**
 * SIEM (Splunk / Elastic / Datadog) 으로 이벤트를 흘리는 포트 (ADR-0012).
 *
 * <p>구현체는 Kafka producer 또는 직접 SIEM HTTP API. 본 모듈은 *Kafka 매개* 구현
 * (auth.audit topic) 을 기본으로 두지만, 인터페이스만 보면 매개체에 비의존.
 *
 * <p>at-least-once — publish 가 실패하면 호출자 (outbox worker) 가 재시도. 같은 이벤트가
 * 두 번 도달할 수 있어 consumer 측에서 eventId 기반 dedup 필요.
 */
public interface SiemEventPublisher {

    /**
     * 발행. 실패 시 RuntimeException — 호출자가 outbox row 의 attempt_count 증가 후 재시도.
     *
     * @param topic 토픽 이름. 본 모듈에서는 항상 "auth.audit".
     * @param key 파티션 키 (consumer 측 ordering 보장 단위). tenantId + userId 조합 권장.
     * @param payloadJson 직렬화된 JSON. eventId / occurredAt / actor / action / target ...
     */
    void publish(String topic, String key, String payloadJson);
}
