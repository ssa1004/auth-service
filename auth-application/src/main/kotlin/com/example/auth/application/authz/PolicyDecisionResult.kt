package com.example.auth.application.authz

import java.util.TreeMap

/**
 * 정책 평가 결과. allow 외에 reason / obligation 을 함께 노출하여 거부 시 사유를 audit 와
 * 응답에 활용 (OPA 의 decision document 표준 형태와 일치).
 *
 * 방어적 복사가 있어 일반 `class` + `@get:JvmName` 으로 record-style accessor 호환.
 *
 * @param allow       최종 허용 여부.
 * @param reasons     거부 또는 허용의 사유 목록. UI 노출 / audit 기록용.
 * @param obligations 정책이 함께 반환한 추가 제약 (예: TTL 단축, 추가 MFA 요구). 호출자가
 *                    소비할 수 있는 자유 형식 map. RFC 7662 introspection 의 obligation
 *                    개념과 같은 의미.
 */
class PolicyDecisionResult(
    allow: Boolean,
    reasons: List<String>?,
    obligations: Map<String, Any?>?,
) {

    @get:JvmName("allow")
    val allow: Boolean = allow

    @get:JvmName("reasons")
    val reasons: List<String> =
        if (reasons == null) emptyList() else java.util.List.copyOf(reasons)

    @get:JvmName("obligations")
    val obligations: Map<String, Any?> =
        if (obligations == null) emptyMap() else java.util.Map.copyOf(TreeMap(obligations))

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PolicyDecisionResult) return false
        return allow == other.allow &&
            reasons == other.reasons &&
            obligations == other.obligations
    }

    override fun hashCode(): Int {
        var result = allow.hashCode()
        result = 31 * result + reasons.hashCode()
        result = 31 * result + obligations.hashCode()
        return result
    }

    override fun toString(): String =
        "PolicyDecisionResult[allow=$allow, reasons=$reasons, obligations=$obligations]"

    companion object {
        /**
         * 정책 평가 결과 — 허용. record 의 component accessor `allow()` 와 이름이 겹치지
         * 않도록 정적 팩토리는 `allowed` / `denied` 로 명명한다.
         */
        @JvmStatic
        fun allowed(): PolicyDecisionResult = PolicyDecisionResult(true, emptyList(), emptyMap())

        @JvmStatic
        fun allowed(reasons: List<String>): PolicyDecisionResult =
            PolicyDecisionResult(true, reasons, emptyMap())

        @JvmStatic
        fun denied(reason: String): PolicyDecisionResult =
            PolicyDecisionResult(false, listOf(reason), emptyMap())

        @JvmStatic
        fun denied(reasons: List<String>): PolicyDecisionResult =
            PolicyDecisionResult(false, reasons, emptyMap())
    }
}
