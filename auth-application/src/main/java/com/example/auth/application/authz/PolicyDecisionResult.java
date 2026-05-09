package com.example.auth.application.authz;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * 정책 평가 결과. allow 외에 reason / obligation 을 함께 노출하여 거부 시 사유를 audit 와
 * 응답에 활용 (OPA 의 decision document 표준 형태와 일치).
 *
 * @param allow       최종 허용 여부.
 * @param reasons     거부 또는 허용의 사유 목록. UI 노출 / audit 기록용.
 * @param obligations 정책이 함께 반환한 추가 제약 (예: TTL 단축, 추가 MFA 요구). 호출자가
 *                    소비할 수 있는 자유 형식 map. RFC 7662 introspection 의 obligation
 *                    개념과 같은 의미.
 */
public record PolicyDecisionResult(
        boolean allow,
        List<String> reasons,
        Map<String, Object> obligations) {

    public PolicyDecisionResult {
        reasons = reasons == null ? List.of() : List.copyOf(reasons);
        obligations = obligations == null ? Map.of() : Map.copyOf(new TreeMap<>(obligations));
    }

    /** 정책 평가 결과 — 허용. record 의 component accessor {@code allow()} 와 이름이 겹치지
     *  않도록 정적 팩토리는 {@code allowed} / {@code denied} 로 명명한다. */
    public static PolicyDecisionResult allowed() {
        return new PolicyDecisionResult(true, List.of(), Map.of());
    }

    public static PolicyDecisionResult allowed(List<String> reasons) {
        return new PolicyDecisionResult(true, reasons, Map.of());
    }

    public static PolicyDecisionResult denied(String reason) {
        Objects.requireNonNull(reason, "reason");
        return new PolicyDecisionResult(false, List.of(reason), Map.of());
    }

    public static PolicyDecisionResult denied(List<String> reasons) {
        return new PolicyDecisionResult(false, reasons, Map.of());
    }
}
