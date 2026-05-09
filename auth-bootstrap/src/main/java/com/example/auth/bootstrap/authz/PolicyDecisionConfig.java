package com.example.auth.bootstrap.authz;

import com.example.auth.adapter.out.authz.EmbeddedPolicyDecisionAdapter;
import com.example.auth.adapter.out.authz.OpaRestPolicyDecisionAdapter;
import com.example.auth.application.authz.PolicyDecisionPort;
import com.example.auth.application.security.AuthProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * {@link PolicyDecisionPort} 빈 선택 — yml 의 {@code auth.opa.mode} 에 따라 embedded /
 * sidecar 분기 (ADR-0016).
 *
 * <ul>
 *   <li>{@code embedded} (기본) — Java 안 정책 평가기. 외부 의존 없음. 단위 / 통합 / dev.</li>
 *   <li>{@code sidecar} — 같은 pod 의 OPA daemon 에 REST 호출. 정책 hot reload 가능.</li>
 * </ul>
 */
@Slf4j
@Configuration
public class PolicyDecisionConfig {

    @Bean
    public PolicyDecisionPort policyDecisionPort(AuthProperties properties, ObjectMapper objectMapper) {
        AuthProperties.Opa opa = properties.opa();
        String mode = opa == null || opa.mode() == null ? "embedded" : opa.mode();
        if ("sidecar".equalsIgnoreCase(mode)) {
            if (opa.baseUrl() == null) {
                throw new IllegalStateException(
                        "auth.opa.mode=sidecar 인데 auth.opa.base-url 이 비어 있음");
            }
            log.info("OPA sidecar 모드 — baseUrl={}, timeout={}ms",
                    opa.baseUrl(), opa.callTimeout().toMillis());
            return new OpaRestPolicyDecisionAdapter(opa.baseUrl(), opa.callTimeout(), objectMapper);
        }
        log.info("OPA embedded 모드 — in-process 평가기 사용");
        return new EmbeddedPolicyDecisionAdapter();
    }
}
