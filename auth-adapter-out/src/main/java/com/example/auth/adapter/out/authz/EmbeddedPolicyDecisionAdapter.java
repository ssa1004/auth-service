package com.example.auth.adapter.out.authz;

import com.example.auth.application.authz.PolicyDecisionPort;
import com.example.auth.application.authz.PolicyDecisionRequest;
import com.example.auth.application.authz.PolicyDecisionResult;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * In-process 정책 평가기 (ADR-0016 의 embedded 모드).
 *
 * <p>OPA daemon 없이 단위 / 통합 테스트와 로컬 개발 환경에서 정책을 평가합니다. policies/
 * 디렉토리의 Rego 정책을 *동등하게* Java 로 구현 — Rego 가 권위 있는 정의이고 본 클래스는
 * 운영 OPA 가 다운됐을 때 fallback 또는 테스트 측 빠른 평가용입니다.
 *
 * <p>운영에서는 sidecar OPA + {@link OpaRestPolicyDecisionAdapter} 를 권장 — 정책 변경이
 * 코드 재배포로 이어지는 것을 막기 위함. embedded 가 Rego 인터프리터를 가져오면 정책 hot
 * reload 도 가능하지만 본 시점에서는 그 작업의 가치가 작아 미도입.
 *
 * <p><strong>주의</strong>: Rego 와 본 Java 구현이 어긋나면 정책 평가 결과가 환경에 따라
 * 달라집니다. CI 에서 두 구현체에 같은 입력을 넣어 결과가 같은지 비교하는 회귀 테스트가
 * 후속으로 추가되어야 합니다.
 */
public class EmbeddedPolicyDecisionAdapter implements PolicyDecisionPort {

    @Override
    public PolicyDecisionResult evaluate(String policyPath, PolicyDecisionRequest request) {
        return switch (policyPath) {
            case "auth/session/revoke" -> sessionRevoke(request);
            case "auth/role/assign" -> roleAssign(request);
            case "auth/refresh/grace" -> refreshGrace(request);
            case "auth/tenant/isolation" -> tenantIsolation(request);
            case "auth/token/revoke" -> tokenRevoke(request);
            default -> PolicyDecisionResult.denied("unknown_policy_path");
        };
    }

    private PolicyDecisionResult tokenRevoke(PolicyDecisionRequest req) {
        // policies/token_revocation.rego 의 in-process 평가. clientId 와 scopes 만 결정 입력.
        Object scopesObj = req.subject().attributes().get("scopes");
        Object clientIdObj = req.subject().attributes().get("clientId");
        boolean hasScope = false;
        if (scopesObj instanceof java.util.Collection<?> col) {
            for (Object s : col) {
                if ("token.revoke".equals(String.valueOf(s))) { hasScope = true; break; }
            }
        }
        boolean hasClientId = clientIdObj != null && !String.valueOf(clientIdObj).isBlank();
        if (hasScope && hasClientId) return PolicyDecisionResult.allowed();

        List<String> reasons = new ArrayList<>();
        if (!hasScope) reasons.add("missing_token_revoke_scope");
        if (!hasClientId) reasons.add("missing_client_id");
        return PolicyDecisionResult.denied(reasons);
    }

    private PolicyDecisionResult sessionRevoke(PolicyDecisionRequest req) {
        var subject = req.subject();
        var resource = req.resource();
        Objects.requireNonNull(resource, "session.revoke 는 resource 필수");

        // 본인 세션
        boolean isSelf = subject.userId().equals(resource.ownerUser())
                && subject.tenantId().equals(resource.ownerTenant());
        if (isSelf) return PolicyDecisionResult.allowed();

        // 같은 테넌트 + platform_admin
        boolean sameTenant = subject.tenantId().equals(resource.ownerTenant());
        boolean platformAdmin = subject.roles().contains("platform_admin");
        boolean globalAdmin = subject.roles().contains("global_admin");

        if (globalAdmin) return PolicyDecisionResult.allowed();
        if (sameTenant && platformAdmin) return PolicyDecisionResult.allowed();

        List<String> reasons = new ArrayList<>();
        if (!sameTenant && !globalAdmin) reasons.add("cross_tenant_access");
        if (!isSelf && !platformAdmin && !globalAdmin) reasons.add("not_resource_owner");
        return PolicyDecisionResult.denied(reasons);
    }

    private PolicyDecisionResult roleAssign(PolicyDecisionRequest req) {
        var subject = req.subject();
        var resource = req.resource();
        Objects.requireNonNull(resource, "role.assign 는 resource 필수");

        Object roleSlugObj = resource.attributes().get("roleSlug");
        String roleSlug = roleSlugObj == null ? "" : roleSlugObj.toString();
        boolean isAdminRole = roleSlug.startsWith("platform_admin")
                || roleSlug.startsWith("senior_admin")
                || roleSlug.equals("global_admin");

        boolean sameTenant = subject.tenantId().equals(resource.ownerTenant());
        boolean platformAdmin = subject.roles().contains("platform_admin");
        boolean seniorAdmin = subject.roles().contains("senior_admin");
        boolean globalAdmin = subject.roles().contains("global_admin");

        if (globalAdmin) return PolicyDecisionResult.allowed();
        if (sameTenant && isAdminRole && seniorAdmin) return PolicyDecisionResult.allowed();
        if (sameTenant && !isAdminRole && platformAdmin) return PolicyDecisionResult.allowed();

        List<String> reasons = new ArrayList<>();
        if (!sameTenant) reasons.add("tenant_mismatch");
        if (isAdminRole && !seniorAdmin && !globalAdmin) reasons.add("admin_role_requires_senior_admin");
        if (!isAdminRole && !platformAdmin && !globalAdmin) reasons.add("missing_platform_admin");
        return PolicyDecisionResult.denied(reasons);
    }

    private PolicyDecisionResult refreshGrace(PolicyDecisionRequest req) {
        Object sameNetwork = req.context().get("sameNetwork");
        Object since = req.context().get("secondsSinceRotation");
        Object grace = req.context().get("graceWindowSeconds");
        boolean sameNet = Boolean.TRUE.equals(sameNetwork);
        long sinceL = toLong(since);
        long graceL = toLong(grace);
        if (sameNet && sinceL <= graceL) {
            return PolicyDecisionResult.allowed();
        }
        List<String> reasons = new ArrayList<>();
        if (!sameNet) reasons.add("different_network");
        if (sinceL > graceL) reasons.add("outside_grace_window");
        return PolicyDecisionResult.denied(reasons);
    }

    private PolicyDecisionResult tenantIsolation(PolicyDecisionRequest req) {
        var subject = req.subject();
        var resource = req.resource();
        if (resource == null) return PolicyDecisionResult.denied("missing_resource");
        if (subject.tenantId().equals(resource.ownerTenant())) {
            return PolicyDecisionResult.allowed();
        }
        if (subject.roles().contains("global_admin")) {
            return PolicyDecisionResult.allowed();
        }
        return PolicyDecisionResult.denied("tenant_mismatch");
    }

    private static long toLong(Object o) {
        if (o == null) return 0;
        if (o instanceof Number n) return n.longValue();
        try { return Long.parseLong(o.toString()); } catch (NumberFormatException e) { return 0; }
    }
}
