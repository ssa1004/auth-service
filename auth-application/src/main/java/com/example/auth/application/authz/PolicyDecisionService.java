package com.example.auth.application.authz;

import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.domain.audit.AuditEventType;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * {@link PolicyDecisionPort} 호출 + 결정 로깅 + audit 기록 합성 (ADR-0016 의 Decision log).
 *
 * <p>호출자는 RBAC (Spring Security {@code @PreAuthorize}) 검증을 통과한 시점에서 추가로
 * 이 서비스를 호출합니다 (defense-in-depth). RBAC + ABAC 둘 다 통과해야 권한이 부여됩니다.
 *
 * <p>모든 결정은 audit_entries 에 한 줄 — 컴플라이언스 / 사후 분석 / "왜 거부됐는지"
 * 디버깅 모두 같은 로그로 추적 가능.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PolicyDecisionService {

    private final PolicyDecisionPort port;
    private final AuditLoginAttemptsUseCase auditUseCase;

    /**
     * 정책 평가 + audit. 거부 시 호출자가 즉시 예외를 던질 책임이 있습니다 — 본 서비스는
     * 결과만 리턴.
     */
    public PolicyDecisionResult evaluate(String policyPath, PolicyDecisionRequest request) {
        PolicyDecisionResult result;
        try {
            result = port.evaluate(policyPath, request);
        } catch (RuntimeException e) {
            // port 구현체가 fail-closed 로 deny 를 반환하는 것이 계약이지만, 방어적으로 한 번 더.
            log.warn("정책 평가 중 예외 — fail-closed 로 deny. policy={} action={}",
                    policyPath, request.action(), e);
            result = PolicyDecisionResult.denied("policy_evaluation_error");
        }

        // 결정 자체를 audit 에. SIEM 에서 "어떤 정책이 무엇을 거부했나" 가 그대로 검색 가능.
        Map<String, String> payload = new LinkedHashMap<>();
        payload.put("policyPath", policyPath);
        payload.put("action", request.action());
        payload.put("allow", Boolean.toString(result.allow()));
        payload.put("reasons", String.join(",", result.reasons()));
        if (request.resource() != null) {
            payload.put("resourceType", request.resource().type());
            if (request.resource().ownerUser() != null) {
                payload.put("resourceOwnerUserId", request.resource().ownerUser().asString());
            }
        }
        try {
            auditUseCase.record(
                    request.subject().tenantId(),
                    request.subject().userId(),
                    result.allow() ? AuditEventType.POLICY_DECISION_ALLOW
                                   : AuditEventType.POLICY_DECISION_DENY,
                    stringOrNull(request.context().get("ip")),
                    stringOrNull(request.context().get("userAgent")),
                    payload);
        } catch (RuntimeException e) {
            // audit 실패가 정책 결과 자체를 덮으면 안 됨.
            log.warn("정책 결정 audit 적재 실패 — 결과는 그대로 반환", e);
        }
        return result;
    }

    private static String stringOrNull(Object o) {
        return o == null ? null : o.toString();
    }
}
