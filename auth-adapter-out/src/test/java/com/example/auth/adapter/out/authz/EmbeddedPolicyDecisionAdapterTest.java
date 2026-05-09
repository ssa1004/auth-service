package com.example.auth.adapter.out.authz;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.application.authz.PolicyDecisionRequest;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * embedded 정책 평가기가 policies/*.rego 와 동등한 결정을 내리는지 검증.
 *
 * <p>각 정책별로 대표 케이스 (allow / deny) 를 모두 체크합니다 — Rego 가 권위 있는 정의
 * 이므로 향후 Rego 가 바뀌면 본 테스트도 동시에 업데이트되어야 합니다.
 */
class EmbeddedPolicyDecisionAdapterTest {

    private final EmbeddedPolicyDecisionAdapter adapter = new EmbeddedPolicyDecisionAdapter();

    @Test
    void session_revoke_본인_세션은_허용() {
        TenantId t = TenantId.newId();
        UserId u = UserId.of(UUID.randomUUID());
        var result = adapter.evaluate("auth/session/revoke", request(
                t, u, Set.of("user"), "session.revoke", t, u));

        assertThat(result.allow()).isTrue();
    }

    @Test
    void session_revoke_다른_사용자_세션은_거부_사유_명시() {
        TenantId t = TenantId.newId();
        UserId actor = UserId.of(UUID.randomUUID());
        UserId victim = UserId.of(UUID.randomUUID());
        var result = adapter.evaluate("auth/session/revoke", request(
                t, actor, Set.of("user"), "session.revoke", t, victim));

        assertThat(result.allow()).isFalse();
        assertThat(result.reasons()).contains("not_resource_owner");
    }

    @Test
    void session_revoke_platform_admin_은_같은_테넌트_안에서_허용() {
        TenantId t = TenantId.newId();
        UserId actor = UserId.of(UUID.randomUUID());
        UserId victim = UserId.of(UUID.randomUUID());
        var result = adapter.evaluate("auth/session/revoke", request(
                t, actor, Set.of("user", "platform_admin"), "session.revoke", t, victim));

        assertThat(result.allow()).isTrue();
    }

    @Test
    void session_revoke_cross_tenant_은_global_admin_만() {
        TenantId t1 = TenantId.newId();
        TenantId t2 = TenantId.newId();
        UserId actor = UserId.of(UUID.randomUUID());
        UserId victim = UserId.of(UUID.randomUUID());
        var denied = adapter.evaluate("auth/session/revoke", request(
                t1, actor, Set.of("platform_admin"), "session.revoke", t2, victim));
        assertThat(denied.allow()).isFalse();
        assertThat(denied.reasons()).contains("cross_tenant_access");

        var allowed = adapter.evaluate("auth/session/revoke", request(
                t1, actor, Set.of("global_admin"), "session.revoke", t2, victim));
        assertThat(allowed.allow()).isTrue();
    }

    @Test
    void role_assign_admin_role_은_senior_admin_만() {
        TenantId t = TenantId.newId();
        UserId actor = UserId.of(UUID.randomUUID());
        UserId target = UserId.of(UUID.randomUUID());
        var deniedPlatformAdmin = adapter.evaluate("auth/role/assign", requestWithRole(
                t, actor, Set.of("platform_admin"), target, "platform_admin"));
        assertThat(deniedPlatformAdmin.allow()).isFalse();
        assertThat(deniedPlatformAdmin.reasons()).contains("admin_role_requires_senior_admin");

        var allowedSenior = adapter.evaluate("auth/role/assign", requestWithRole(
                t, actor, Set.of("senior_admin"), target, "platform_admin"));
        assertThat(allowedSenior.allow()).isTrue();
    }

    @Test
    void role_assign_일반_role_은_platform_admin_도_가능() {
        TenantId t = TenantId.newId();
        UserId actor = UserId.of(UUID.randomUUID());
        UserId target = UserId.of(UUID.randomUUID());
        var allowed = adapter.evaluate("auth/role/assign", requestWithRole(
                t, actor, Set.of("platform_admin"), target, "billing-operator"));
        assertThat(allowed.allow()).isTrue();
    }

    @Test
    void refresh_grace_같은_네트워크_와_윈도우_안이면_허용() {
        var allow = adapter.evaluate("auth/refresh/grace", graceRequest(true, 3, 5));
        assertThat(allow.allow()).isTrue();

        var differentNetwork = adapter.evaluate("auth/refresh/grace", graceRequest(false, 3, 5));
        assertThat(differentNetwork.allow()).isFalse();
        assertThat(differentNetwork.reasons()).contains("different_network");

        var outsideWindow = adapter.evaluate("auth/refresh/grace", graceRequest(true, 10, 5));
        assertThat(outsideWindow.allow()).isFalse();
        assertThat(outsideWindow.reasons()).contains("outside_grace_window");
    }

    @Test
    void 알_수_없는_정책_path_는_deny() {
        TenantId t = TenantId.newId();
        UserId u = UserId.of(UUID.randomUUID());
        var result = adapter.evaluate("auth/unknown/path", request(
                t, u, Set.of(), "unknown", t, u));
        assertThat(result.allow()).isFalse();
        assertThat(result.reasons()).contains("unknown_policy_path");
    }

    private PolicyDecisionRequest request(
            TenantId subjectTenant, UserId subjectUser, Set<String> roles,
            String action, TenantId resourceTenant, UserId resourceUser) {
        return new PolicyDecisionRequest(
                new PolicyDecisionRequest.Subject(
                        subjectTenant, subjectUser, roles, Set.of(), Map.of()),
                action,
                new PolicyDecisionRequest.Resource(
                        "session", resourceTenant, resourceUser, Map.of()),
                Map.of());
    }

    private PolicyDecisionRequest requestWithRole(
            TenantId tenant, UserId actor, Set<String> actorRoles, UserId target, String roleSlug) {
        return new PolicyDecisionRequest(
                new PolicyDecisionRequest.Subject(
                        tenant, actor, actorRoles, Set.of(), Map.of()),
                "role.assign",
                new PolicyDecisionRequest.Resource(
                        "role", tenant, target, Map.of("roleSlug", (Object) roleSlug)),
                Map.of());
    }

    private PolicyDecisionRequest graceRequest(boolean sameNetwork, long sinceSec, long graceSec) {
        TenantId t = TenantId.newId();
        UserId u = UserId.of(UUID.randomUUID());
        return new PolicyDecisionRequest(
                new PolicyDecisionRequest.Subject(t, u, Set.of(), Set.of(), Map.of()),
                "refresh.grace",
                new PolicyDecisionRequest.Resource("refresh_token", t, u, Map.of()),
                Map.of(
                        "sameNetwork", sameNetwork,
                        "secondsSinceRotation", sinceSec,
                        "graceWindowSeconds", graceSec));
    }
}
