package com.example.auth.adapter.out.siem

import com.example.auth.application.port.out.SiemEventPublisher
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.stereotype.Component

/**
 * 기본 (dev / local) [SiemEventPublisher] 구현 — 로그로만 출력.
 *
 * 운영에서는 Kafka 또는 SIEM HTTP API 로 보내는 구현으로 교체.
 * Spring Kafka 라이브러리를 본 모듈에 강제 의존하지 않기 위해 인터페이스만 추상화하고,
 * 운영 wiring 은 별도 모듈 또는 prod profile 빈으로 등록.
 *
 * [ConditionalOnMissingBean] — Kafka 구현이 등록되면 자동 비활성.
 */
@Component
@ConditionalOnMissingBean(name = ["kafkaSiemEventPublisher"])
class LoggingSiemEventPublisher : SiemEventPublisher {

    override fun publish(topic: String, key: String, payloadJson: String) {
        // dev/local — 실 SIEM 없음. payload 는 *이미* 마스킹된 JSON 이라 평문 비밀번호 /
        // 토큰이 없어야 한다 (호출자 의무 — ADR-0008).
        log.info("[SIEM-DEV] topic={} key={} payload={}", topic, key, payloadJson)
    }

    private companion object {
        val log = LoggerFactory.getLogger(LoggingSiemEventPublisher::class.java)
    }
}
