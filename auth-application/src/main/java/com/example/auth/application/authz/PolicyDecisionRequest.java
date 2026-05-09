package com.example.auth.application.authz;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * ABAC 정책 평가 요청 — subject / action / resource / context 4 튜플 (NIST SP 800-162).
 *
 * <p>RBAC 만으로 표현하기 어려운 조건부 권한 (예: "본인 세션만 revoke 가능", "다른 테넌트
 * 사용자에 admin role 부여 금지") 을 정책 엔진이 평가하도록 격리시키는 입력 객체.
 *
 * <p>모든 필드는 nullable 가능 — 정책별로 필요한 attribute 만 채우면 됨.
 *
 * @param subject  요청자 (actor) 의 속성. tenantId, userId, roles, permissions 등.
 * @param action   수행하려는 행위 식별자 (예: "session.revoke", "role.assign", "refresh.grace").
 * @param resource 행위 대상 리소스 (예: 다른 사용자의 세션, role 객체). nullable.
 * @param context  요청 컨텍스트 (IP, userAgent, time, requestId 등). 시간 / 위치 조건을
 *                 정책에서 평가할 때 사용.
 */
public record PolicyDecisionRequest(
        Subject subject,
        String action,
        Resource resource,
        Map<String, Object> context) {

    public PolicyDecisionRequest {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(action, "action");
        if (action.isBlank()) {
            throw new IllegalArgumentException("action 은 비어있을 수 없습니다");
        }
        // 정렬된 immutable view — Rego 평가 측 직렬화 안정성.
        context = context == null ? Map.of() : Map.copyOf(new TreeMap<>(context));
    }

    /**
     * 요청자 속성. JWT claim 에 들어가는 RBAC 정보 + 그 위 ABAC 평가용 추가 속성.
     */
    public record Subject(
            TenantId tenantId,
            UserId userId,
            Set<String> roles,
            Set<String> permissions,
            Map<String, Object> attributes) {

        public Subject {
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(userId, "userId");
            roles = roles == null ? Set.of() : Set.copyOf(roles);
            permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
            attributes = attributes == null ? Map.of() : Map.copyOf(new TreeMap<>(attributes));
        }
    }

    /**
     * 행위 대상. 같은 사용자가 자기 자신의 자원을 다루는지, 다른 사용자의 자원을 다루는지
     * 정책이 판별하기 위한 입력.
     *
     * @param type        리소스 종류 (예: "session", "role", "refresh_token", "user").
     * @param ownerTenant 리소스를 소유한 테넌트. cross-tenant 접근 차단에 사용.
     * @param ownerUser   리소스를 소유한 사용자. nullable (테넌트 자체 자원은 null).
     * @param attributes  리소스별 추가 속성.
     */
    public record Resource(
            String type,
            TenantId ownerTenant,
            UserId ownerUser,
            Map<String, Object> attributes) {

        public Resource {
            Objects.requireNonNull(type, "type");
            attributes = attributes == null ? Map.of() : Map.copyOf(new TreeMap<>(attributes));
        }
    }
}
