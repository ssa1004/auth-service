package com.example.auth.application.exception;

import java.util.List;

/**
 * ABAC 정책이 행위를 거부할 때 throw. RBAC 통과 후의 추가 검증에서 막혔다는 뜻이라
 * 사용자 입력 오류가 아닌 정책 위반.
 */
public class PolicyDeniedException extends RuntimeException {

    private final List<String> reasons;

    public PolicyDeniedException(List<String> reasons) {
        super("정책 평가에서 거부: " + String.join(",", reasons == null ? List.of() : reasons));
        this.reasons = reasons == null ? List.of() : List.copyOf(reasons);
    }

    public List<String> reasons() {
        return reasons;
    }
}
