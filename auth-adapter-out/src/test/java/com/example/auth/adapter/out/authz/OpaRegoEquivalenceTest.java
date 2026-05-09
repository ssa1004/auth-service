package com.example.auth.adapter.out.authz;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.application.authz.PolicyDecisionRequest;
import com.example.auth.application.authz.PolicyDecisionResult;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * Embedded 어댑터와 실제 OPA daemon (sidecar 모드) 의 결정이 같은 입력에 대해 같은
 * allow/deny + 같은 reason 집합을 내는지 검증하는 회귀 테스트.
 *
 * <p>운영에서 정책 hot reload 를 위해 sidecar OPA 모드를 쓰는데 (ADR-0016), embedded 와
 * Rego 가 어긋나면 환경별로 인가 결정이 달라집니다. CI 가 OPA 컨테이너를 띄워 같은 케이스
 * 매트릭스를 두 어댑터에 통과시켜 결과를 비교합니다 — Rego 가 권위 있는 정의이므로 어긋날
 * 때는 embedded 가 따라가야 합니다.
 *
 * <p>Docker 가 없는 환경에서는 Testcontainers 가 자동으로 skip 처리하므로 로컬 IDE 만
 * 돌리는 개발자도 무리 없이 빌드 가능합니다.
 */
class OpaRegoEquivalenceTest {

    /**
     * OPA 0.69.0 — Rego v1 (`import rego.v1`) 를 정식 지원. 본 정책 파일들이 v1 syntax 라
     * 0.61.0 이상 필요. 운영도 같은 버전 / 마이너로 고정해 정책 평가 시맨틱 변경 회피.
     */
    private static final DockerImageName OPA_IMAGE = DockerImageName.parse("openpolicyagent/opa:0.69.0");

    private static GenericContainer<?> opa;
    private static OpaRestPolicyDecisionAdapter rego;
    private static EmbeddedPolicyDecisionAdapter embedded;
    private static final ObjectMapper OM = new ObjectMapper();

    @BeforeAll
    static void startOpa() {
        // policies/ 디렉토리는 repo root 기준. 모듈 안에서 실행되므로 ../policies 로 접근.
        Path policiesDir = locatePoliciesDir();
        opa = new GenericContainer<>(OPA_IMAGE)
                .withCommand("run", "--server", "--addr", "0.0.0.0:8181", "--log-level", "error", "/policies")
                .withCopyFileToContainer(MountableFile.forHostPath(policiesDir), "/policies")
                .withExposedPorts(8181)
                .waitingFor(Wait.forHttp("/health").forStatusCode(200));
        opa.start();

        URI baseUrl = URI.create("http://" + opa.getHost() + ":" + opa.getMappedPort(8181));
        rego = new OpaRestPolicyDecisionAdapter(baseUrl, Duration.ofSeconds(2), OM);
        embedded = new EmbeddedPolicyDecisionAdapter();
    }

    @AfterAll
    static void stopOpa() {
        if (opa != null) opa.stop();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void embedded_와_rego_가_같은_결정을_낸다(String name, String policyPath, PolicyDecisionRequest request) {
        PolicyDecisionResult regoResult = rego.evaluate(policyPath, request);
        PolicyDecisionResult embeddedResult = embedded.evaluate(policyPath, request);

        assertThat(embeddedResult.allow())
                .as("allow 가 일치해야 함 (case=%s, rego=%s, embedded=%s)",
                        name, regoResult.allow(), embeddedResult.allow())
                .isEqualTo(regoResult.allow());

        // reason 집합 비교 — 순서/중복 무관. allow=true 케이스는 둘 다 reason 비어있어야 함.
        if (regoResult.allow()) {
            assertThat(embeddedResult.reasons())
                    .as("allow=true 시 embedded reason 도 비어있어야 함 (case=%s)", name)
                    .isEmpty();
            assertThat(regoResult.reasons())
                    .as("allow=true 시 Rego reason 도 비어있어야 함 (case=%s)", name)
                    .isEmpty();
        } else {
            assertThat(setOf(embeddedResult.reasons()))
                    .as("deny reason 집합이 일치해야 함 (case=%s, rego=%s, embedded=%s)",
                            name, regoResult.reasons(), embeddedResult.reasons())
                    .isEqualTo(setOf(regoResult.reasons()));
        }
    }

    /**
     * 케이스 매트릭스 — 5개 정책 × allow/deny 양끝 + 거부 사유 분리. 새로운 정책이나 reason
     * 분기를 추가하면 본 매트릭스도 함께 늘려야 회귀 보호가 유지됩니다.
     */
    static Stream<org.junit.jupiter.params.provider.Arguments> cases() {
        TenantId tenantA = TenantId.newId();
        TenantId tenantB = TenantId.newId();
        UserId actor = UserId.of(UUID.randomUUID());
        UserId victim = UserId.of(UUID.randomUUID());
        UserId target = UserId.of(UUID.randomUUID());

        return Stream.of(
                // session/revoke
                arg("session/self", "auth/session/revoke",
                        sessionReq(tenantA, actor, Set.of("user"), tenantA, actor)),
                arg("session/other_user_same_tenant_normal_user_denied", "auth/session/revoke",
                        sessionReq(tenantA, actor, Set.of("user"), tenantA, victim)),
                arg("session/other_user_same_tenant_platform_admin_allowed", "auth/session/revoke",
                        sessionReq(tenantA, actor, Set.of("platform_admin"), tenantA, victim)),
                arg("session/cross_tenant_platform_admin_denied", "auth/session/revoke",
                        sessionReq(tenantA, actor, Set.of("platform_admin"), tenantB, victim)),
                arg("session/cross_tenant_global_admin_allowed", "auth/session/revoke",
                        sessionReq(tenantA, actor, Set.of("global_admin"), tenantB, victim)),

                // role/assign
                arg("role/normal_role_platform_admin_allowed", "auth/role/assign",
                        roleReq(tenantA, actor, Set.of("platform_admin"), tenantA, target, "billing-operator")),
                arg("role/admin_role_platform_admin_denied", "auth/role/assign",
                        roleReq(tenantA, actor, Set.of("platform_admin"), tenantA, target, "platform_admin")),
                arg("role/admin_role_senior_admin_allowed", "auth/role/assign",
                        roleReq(tenantA, actor, Set.of("senior_admin"), tenantA, target, "platform_admin")),
                arg("role/cross_tenant_platform_admin_denied", "auth/role/assign",
                        roleReq(tenantA, actor, Set.of("platform_admin"), tenantB, target, "billing-operator")),
                arg("role/global_admin_cross_tenant_allowed", "auth/role/assign",
                        roleReq(tenantA, actor, Set.of("global_admin"), tenantB, target, "platform_admin")),

                // tenant/isolation
                arg("tenant/same_tenant_allowed", "auth/tenant/isolation",
                        tenantReq(tenantA, actor, Set.of("user"), tenantA)),
                arg("tenant/cross_tenant_user_denied", "auth/tenant/isolation",
                        tenantReq(tenantA, actor, Set.of("user"), tenantB)),
                arg("tenant/cross_tenant_global_admin_allowed", "auth/tenant/isolation",
                        tenantReq(tenantA, actor, Set.of("global_admin"), tenantB)),

                // refresh/grace
                arg("refresh/grace_inside_window_same_network", "auth/refresh/grace",
                        graceReq(tenantA, actor, true, 3, 5)),
                arg("refresh/grace_outside_window", "auth/refresh/grace",
                        graceReq(tenantA, actor, true, 10, 5)),
                arg("refresh/grace_different_network", "auth/refresh/grace",
                        graceReq(tenantA, actor, false, 3, 5)),
                arg("refresh/grace_outside_and_different_network", "auth/refresh/grace",
                        graceReq(tenantA, actor, false, 10, 5)),

                // token/revoke (admin scope 검증)
                arg("token_revoke/has_scope_and_client_id", "auth/token/revoke",
                        tokenRevokeReq("internal-admin", Set.of("token.revoke"))),
                arg("token_revoke/missing_scope", "auth/token/revoke",
                        tokenRevokeReq("internal-service", Set.of("api.read"))),
                arg("token_revoke/missing_client_id", "auth/token/revoke",
                        tokenRevokeReq("", Set.of("token.revoke"))),
                arg("token_revoke/missing_both", "auth/token/revoke",
                        tokenRevokeReq("", Set.of("api.read")))
        );
    }

    private static org.junit.jupiter.params.provider.Arguments arg(
            String name, String policyPath, PolicyDecisionRequest request) {
        return org.junit.jupiter.params.provider.Arguments.of(name, policyPath, request);
    }

    private static PolicyDecisionRequest sessionReq(
            TenantId subjectTenant, UserId subjectUser, Set<String> roles,
            TenantId resourceTenant, UserId resourceUser) {
        return new PolicyDecisionRequest(
                new PolicyDecisionRequest.Subject(
                        subjectTenant, subjectUser, roles, Set.of(), Map.of()),
                "session.revoke",
                new PolicyDecisionRequest.Resource(
                        "session", resourceTenant, resourceUser, Map.of()),
                Map.of());
    }

    private static PolicyDecisionRequest roleReq(
            TenantId subjectTenant, UserId subjectUser, Set<String> roles,
            TenantId resourceTenant, UserId target, String roleSlug) {
        return new PolicyDecisionRequest(
                new PolicyDecisionRequest.Subject(
                        subjectTenant, subjectUser, roles, Set.of(), Map.of()),
                "role.assign",
                new PolicyDecisionRequest.Resource(
                        "role", resourceTenant, target, Map.of("roleSlug", (Object) roleSlug)),
                Map.of());
    }

    private static PolicyDecisionRequest tenantReq(
            TenantId subjectTenant, UserId subjectUser, Set<String> roles, TenantId resourceTenant) {
        return new PolicyDecisionRequest(
                new PolicyDecisionRequest.Subject(
                        subjectTenant, subjectUser, roles, Set.of(), Map.of()),
                "tenant.access",
                new PolicyDecisionRequest.Resource(
                        "tenant", resourceTenant, null, Map.of()),
                Map.of());
    }

    private static PolicyDecisionRequest graceReq(
            TenantId tenant, UserId user, boolean sameNetwork, long sinceSec, long graceSec) {
        return new PolicyDecisionRequest(
                new PolicyDecisionRequest.Subject(tenant, user, Set.of(), Set.of(), Map.of()),
                "refresh.grace",
                new PolicyDecisionRequest.Resource("refresh_token", tenant, user, Map.of()),
                Map.of(
                        "sameNetwork", sameNetwork,
                        "secondsSinceRotation", sinceSec,
                        "graceWindowSeconds", graceSec));
    }

    private static PolicyDecisionRequest tokenRevokeReq(String clientId, Set<String> scopes) {
        // RFC 7009 admin gate — 호출자는 user 가 아니라 client. nil UUID 로 가드 통과.
        UUID nil = new UUID(0L, 0L);
        return new PolicyDecisionRequest(
                new PolicyDecisionRequest.Subject(
                        TenantId.of(nil), UserId.of(nil),
                        Set.of(), Set.of(),
                        Map.of("clientId", clientId, "scopes", scopes)),
                "token.revoke",
                new PolicyDecisionRequest.Resource(
                        "token", TenantId.of(nil), null, Map.of()),
                Map.of());
    }

    private static java.util.Set<String> setOf(List<String> reasons) {
        return new java.util.HashSet<>(reasons == null ? List.<String>of() : reasons);
    }

    /**
     * gradle 의 작업 디렉토리는 모듈 디렉토리. 따라서 repo root 의 policies/ 는 부모 경로.
     * IDE 가 root 에서 실행하면 그대로 policies/. 두 케이스를 모두 안전하게 처리.
     */
    private static Path locatePoliciesDir() {
        List<Path> candidates = new ArrayList<>();
        Path here = Paths.get("").toAbsolutePath();
        candidates.add(here.resolve("policies"));
        candidates.add(here.getParent() == null ? here.resolve("policies") : here.getParent().resolve("policies"));
        for (Path p : candidates) {
            if (Files.isDirectory(p)) return p;
        }
        throw new IllegalStateException(
                "policies/ 디렉토리를 찾지 못함. 시도한 경로: " + candidates);
    }
}
