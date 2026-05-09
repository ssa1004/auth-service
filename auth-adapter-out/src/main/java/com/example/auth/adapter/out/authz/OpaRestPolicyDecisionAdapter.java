package com.example.auth.adapter.out.authz;

import com.example.auth.application.authz.PolicyDecisionPort;
import com.example.auth.application.authz.PolicyDecisionRequest;
import com.example.auth.application.authz.PolicyDecisionResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

/**
 * OPA daemon 에 REST 로 결정 요청을 보내는 adapter (sidecar 모드, ADR-0016).
 *
 * <p>운영 권장 wiring:
 * <ul>
 *   <li>OPA 는 K8s 같은 pod 안 sidecar container 로 배치 — TCP 8181 노출.</li>
 *   <li>본 adapter 는 {@code http://localhost:8181} 으로만 호출 — 네트워크 hop 0.</li>
 *   <li>OPA 는 정책 bundle 을 S3 / git repo 에서 polling 으로 받아 hot reload.</li>
 * </ul>
 *
 * <p>fail-closed — 네트워크 / 5xx 실패 시 deny 로 감싸 반환합니다. 정책 엔진이 죽었을 때
 * 모든 권한 부여가 차단되는 강한 정책. 운영자가 fail-open 이 필요하면 별도 어댑터를 쓰거나
 * yml flag 로 제어해야 합니다 (현재는 의도적으로 미제공).
 */
@Slf4j
public class OpaRestPolicyDecisionAdapter implements PolicyDecisionPort {

    private final RestClient client;
    private final ObjectMapper objectMapper;

    public OpaRestPolicyDecisionAdapter(URI opaBaseUrl, Duration callTimeout, ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.client = RestClient.builder()
                .baseUrl(opaBaseUrl.toString())
                .requestFactory(timeoutRequestFactory(callTimeout))
                .build();
    }

    private static org.springframework.http.client.ClientHttpRequestFactory timeoutRequestFactory(
            Duration callTimeout) {
        var factory = new org.springframework.http.client.SimpleClientHttpRequestFactory();
        // OPA 가 10ms 대 응답이 정상 — 100ms 가 넘으면 정책 엔진 문제 신호. 빠르게 fail-fast.
        factory.setConnectTimeout((int) Math.min(callTimeout.toMillis(), Integer.MAX_VALUE));
        factory.setReadTimeout((int) Math.min(callTimeout.toMillis(), Integer.MAX_VALUE));
        return factory;
    }

    @Override
    public PolicyDecisionResult evaluate(String policyPath, PolicyDecisionRequest request) {
        // OPA REST 규약: POST /v1/data/<package-path-with-slashes>
        // policyPath = "auth/session/revoke" → /v1/data/auth/session/revoke
        String url = "/v1/data/" + policyPath;
        ObjectNode body = OpaInputMarshaller.toInput(objectMapper, request);
        try {
            JsonNode response = client.post()
                    .uri(url)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .retrieve()
                    .body(JsonNode.class);
            return OpaInputMarshaller.parseResponse(response);
        } catch (ResourceAccessException e) {
            // 네트워크 / timeout — OPA sidecar 다운 가능성. fail-closed.
            log.warn("OPA 호출 실패 — fail-closed 로 deny 처리. policy={} url={}", policyPath, url, e);
            return PolicyDecisionResult.denied("opa_unreachable");
        } catch (RuntimeException e) {
            log.warn("OPA 응답 파싱 실패 — fail-closed 로 deny. policy={}", policyPath, e);
            return PolicyDecisionResult.denied("opa_invalid_response");
        }
    }
}
