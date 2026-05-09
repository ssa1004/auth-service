package com.example.auth.application.authz;

/**
 * ABAC 정책 평가 outbound port. 구현체는 OPA REST API 또는 in-process 평가기.
 *
 * <p>RBAC (역할 → 권한) 으로 표현하기 어려운 조건부 정책을 코드 밖 Rego 로 분리하여
 * 정책 변경이 코드 재배포로 이어지지 않도록 합니다 (ADR-0016).
 *
 * <p>호출 방식은 정책 별로 분리된 path — Rego 측 package 와 1:1 대응.
 * 예: {@code "auth/session/revoke"} → OPA path {@code data.auth.session.revoke.allow}.
 */
public interface PolicyDecisionPort {

    /**
     * 정책 평가.
     *
     * @param policyPath 정책 식별자. 슬래시 구분 (예: "auth/session/revoke", "auth/role/assign").
     * @param request    평가 입력.
     * @return 평가 결과. 구현체가 외부 호출에 실패해도 예외를 던지지 않고 {@code deny} 로
     *         감싸 반환합니다 — fail-closed 가 기본 (정책 엔진 장애 시 모든 권한 부여를
     *         차단). 운영에서 정책 엔진 다운으로 전체 서비스가 멈추는 것을 막으려면 호출
     *         site 에서 명시적으로 "정책 엔진 장애 = 잠금" vs "기존 RBAC 만으로 진행" 을
     *         결정해야 합니다.
     */
    PolicyDecisionResult evaluate(String policyPath, PolicyDecisionRequest request);
}
