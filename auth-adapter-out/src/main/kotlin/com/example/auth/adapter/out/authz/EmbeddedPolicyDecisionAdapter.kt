package com.example.auth.adapter.out.authz

import com.example.auth.application.authz.PolicyDecisionPort
import com.example.auth.application.authz.PolicyDecisionRequest
import com.example.auth.application.authz.PolicyDecisionResult

/**
 * In-process 정책 평가기 (ADR-0016 의 embedded 모드).
 *
 * OPA daemon 없이 단위 / 통합 테스트와 로컬 개발 환경에서 정책을 평가합니다. policies/
 * 디렉토리의 Rego 정책을 *동등하게* Kotlin 으로 구현 — Rego 가 권위 있는 정의이고 본 클래스는
 * 운영 OPA 가 다운됐을 때 fallback 또는 테스트 측 빠른 평가용입니다.
 *
 * 운영에서는 sidecar OPA + [OpaRestPolicyDecisionAdapter] 를 권장 — 정책 변경이
 * 코드 재배포로 이어지는 것을 막기 위함. embedded 가 Rego 인터프리터를 가져오면 정책 hot
 * reload 도 가능하지만 본 시점에서는 그 작업의 가치가 작아 미도입.
 *
 * **주의**: Rego 와 본 Kotlin 구현이 어긋나면 정책 평가 결과가 환경에 따라 달라집니다.
 * CI 에서 두 구현체에 같은 입력을 넣어 결과가 같은지 비교하는 회귀 테스트가 후속으로
 * 추가되어야 합니다.
 */
open class EmbeddedPolicyDecisionAdapter : PolicyDecisionPort {

    override fun evaluate(policyPath: String, request: PolicyDecisionRequest): PolicyDecisionResult =
        when (policyPath) {
            "auth/session/revoke" -> sessionRevoke(request)
            "auth/role/assign" -> roleAssign(request)
            "auth/refresh/grace" -> refreshGrace(request)
            "auth/tenant/isolation" -> tenantIsolation(request)
            "auth/token/revoke" -> tokenRevoke(request)
            else -> PolicyDecisionResult.denied("unknown_policy_path")
        }

    private fun tokenRevoke(req: PolicyDecisionRequest): PolicyDecisionResult {
        // policies/token_revocation.rego 의 in-process 평가. clientId 와 scopes 만 결정 입력.
        val scopesObj = req.subject.attributes["scopes"]
        val clientIdObj = req.subject.attributes["clientId"]
        var hasScope = false
        if (scopesObj is Collection<*>) {
            for (s in scopesObj) {
                if (s.toString() == "token.revoke") {
                    hasScope = true
                    break
                }
            }
        }
        val hasClientId = clientIdObj != null && clientIdObj.toString().isNotBlank()
        if (hasScope && hasClientId) return PolicyDecisionResult.allowed()

        val reasons = ArrayList<String>()
        if (!hasScope) reasons.add("missing_token_revoke_scope")
        if (!hasClientId) reasons.add("missing_client_id")
        return PolicyDecisionResult.denied(reasons)
    }

    private fun sessionRevoke(req: PolicyDecisionRequest): PolicyDecisionResult {
        val subject = req.subject
        val resource = requireNotNull(req.resource) { "session.revoke 는 resource 필수" }

        // 본인 세션
        val isSelf = subject.userId == resource.ownerUser &&
            subject.tenantId == resource.ownerTenant
        if (isSelf) return PolicyDecisionResult.allowed()

        // 같은 테넌트 + platform_admin
        val sameTenant = subject.tenantId == resource.ownerTenant
        val platformAdmin = subject.roles.contains("platform_admin")
        val globalAdmin = subject.roles.contains("global_admin")

        if (globalAdmin) return PolicyDecisionResult.allowed()
        if (sameTenant && platformAdmin) return PolicyDecisionResult.allowed()

        val reasons = ArrayList<String>()
        if (!sameTenant && !globalAdmin) reasons.add("cross_tenant_access")
        if (!isSelf && !platformAdmin && !globalAdmin) reasons.add("not_resource_owner")
        return PolicyDecisionResult.denied(reasons)
    }

    private fun roleAssign(req: PolicyDecisionRequest): PolicyDecisionResult {
        val subject = req.subject
        val resource = requireNotNull(req.resource) { "role.assign 는 resource 필수" }

        val roleSlug = resource.attributes["roleSlug"]?.toString() ?: ""
        val isAdminRole = roleSlug.startsWith("platform_admin") ||
            roleSlug.startsWith("senior_admin") ||
            roleSlug == "global_admin"

        val sameTenant = subject.tenantId == resource.ownerTenant
        val platformAdmin = subject.roles.contains("platform_admin")
        val seniorAdmin = subject.roles.contains("senior_admin")
        val globalAdmin = subject.roles.contains("global_admin")

        if (globalAdmin) return PolicyDecisionResult.allowed()
        if (sameTenant && isAdminRole && seniorAdmin) return PolicyDecisionResult.allowed()
        if (sameTenant && !isAdminRole && platformAdmin) return PolicyDecisionResult.allowed()

        val reasons = ArrayList<String>()
        if (!sameTenant) reasons.add("tenant_mismatch")
        if (isAdminRole && !seniorAdmin && !globalAdmin) reasons.add("admin_role_requires_senior_admin")
        if (!isAdminRole && !platformAdmin && !globalAdmin) reasons.add("missing_platform_admin")
        return PolicyDecisionResult.denied(reasons)
    }

    private fun refreshGrace(req: PolicyDecisionRequest): PolicyDecisionResult {
        val sameNetwork = req.context["sameNetwork"]
        val since = req.context["secondsSinceRotation"]
        val grace = req.context["graceWindowSeconds"]
        val sameNet = sameNetwork == true
        val sinceL = toLong(since)
        val graceL = toLong(grace)
        if (sameNet && sinceL <= graceL) {
            return PolicyDecisionResult.allowed()
        }
        val reasons = ArrayList<String>()
        if (!sameNet) reasons.add("different_network")
        if (sinceL > graceL) reasons.add("outside_grace_window")
        return PolicyDecisionResult.denied(reasons)
    }

    private fun tenantIsolation(req: PolicyDecisionRequest): PolicyDecisionResult {
        val subject = req.subject
        val resource = req.resource ?: return PolicyDecisionResult.denied("missing_resource")
        if (subject.tenantId == resource.ownerTenant) {
            return PolicyDecisionResult.allowed()
        }
        if (subject.roles.contains("global_admin")) {
            return PolicyDecisionResult.allowed()
        }
        return PolicyDecisionResult.denied("tenant_mismatch")
    }

    private companion object {
        fun toLong(o: Any?): Long {
            if (o == null) return 0
            if (o is Number) return o.toLong()
            return try {
                o.toString().toLong()
            } catch (e: NumberFormatException) {
                0
            }
        }
    }
}
