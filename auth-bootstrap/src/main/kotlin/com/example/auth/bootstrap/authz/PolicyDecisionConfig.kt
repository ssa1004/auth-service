package com.example.auth.bootstrap.authz

import com.example.auth.adapter.out.authz.EmbeddedPolicyDecisionAdapter
import com.example.auth.adapter.out.authz.OpaRestPolicyDecisionAdapter
import com.example.auth.application.authz.PolicyDecisionPort
import com.example.auth.application.security.AuthProperties
import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * [PolicyDecisionPort] 빈 선택 — yml 의 `auth.opa.mode` 에 따라 embedded /
 * sidecar 분기 (ADR-0016).
 *
 * - `embedded` (기본) — Java 안 정책 평가기. 외부 의존 없음. 단위 / 통합 / dev.
 * - `sidecar` — 같은 pod 의 OPA daemon 에 REST 호출. 정책 hot reload 가능.
 */
@Configuration
open class PolicyDecisionConfig {

    @Bean
    open fun policyDecisionPort(properties: AuthProperties, objectMapper: ObjectMapper): PolicyDecisionPort {
        val opa = properties.opa
        val mode = opa.mode.ifBlank { "embedded" }
        if ("sidecar".equals(mode, ignoreCase = true)) {
            val baseUrl = opa.baseUrl
                ?: throw IllegalStateException("auth.opa.mode=sidecar 인데 auth.opa.base-url 이 비어 있음")
            log.info(
                "OPA sidecar 모드 — baseUrl={}, timeout={}ms",
                baseUrl, opa.callTimeout.toMillis(),
            )
            return OpaRestPolicyDecisionAdapter(baseUrl, opa.callTimeout, objectMapper)
        }
        log.info("OPA embedded 모드 — in-process 평가기 사용")
        return EmbeddedPolicyDecisionAdapter()
    }

    companion object {
        private val log = LoggerFactory.getLogger(PolicyDecisionConfig::class.java)
    }
}
