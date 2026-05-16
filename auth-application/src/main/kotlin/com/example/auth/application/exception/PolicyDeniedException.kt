package com.example.auth.application.exception

/**
 * ABAC 정책이 행위를 거부할 때 throw. RBAC 통과 후의 추가 검증에서 막혔다는 뜻이라
 * 사용자 입력 오류가 아닌 정책 위반.
 */
class PolicyDeniedException(reasons: List<String>?) :
    RuntimeException("정책 평가에서 거부: " + (reasons ?: emptyList()).joinToString(",")) {

    private val reasonsCopy: List<String> =
        if (reasons == null) emptyList() else java.util.List.copyOf(reasons)

    fun reasons(): List<String> = reasonsCopy
}
