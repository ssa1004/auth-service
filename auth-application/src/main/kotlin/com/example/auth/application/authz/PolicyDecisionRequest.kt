package com.example.auth.application.authz

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import java.util.TreeMap

/**
 * ABAC 정책 평가 요청 — subject / action / resource / context 4 튜플 (NIST SP 800-162).
 *
 * RBAC 만으로 표현하기 어려운 조건부 권한 (예: "본인 세션만 revoke 가능", "다른 테넌트
 * 사용자에 admin role 부여 금지") 을 정책 엔진이 평가하도록 격리시키는 입력 객체.
 *
 * 모든 필드는 nullable 가능 — 정책별로 필요한 attribute 만 채우면 됨.
 *
 * 방어적 복사가 있어 일반 `class` + `@get:JvmName` 으로 record-style accessor 호환.
 *
 * @param subject  요청자 (actor) 의 속성. tenantId, userId, roles, permissions 등.
 * @param action   수행하려는 행위 식별자 (예: "session.revoke", "role.assign", "refresh.grace").
 * @param resource 행위 대상 리소스 (예: 다른 사용자의 세션, role 객체). nullable.
 * @param context  요청 컨텍스트 (IP, userAgent, time, requestId 등). 시간 / 위치 조건을
 *                 정책에서 평가할 때 사용.
 */
class PolicyDecisionRequest(
    subject: Subject,
    action: String,
    resource: Resource?,
    context: Map<String, Any?>?,
) {

    @get:JvmName("subject")
    val subject: Subject = subject

    @get:JvmName("action")
    val action: String = action

    @get:JvmName("resource")
    val resource: Resource? = resource

    @get:JvmName("context")
    val context: Map<String, Any?>

    init {
        require(action.isNotBlank()) { "action 은 비어있을 수 없습니다" }
        // 정렬된 immutable view — Rego 평가 측 직렬화 안정성.
        this.context =
            if (context == null) emptyMap() else java.util.Map.copyOf(TreeMap(context))
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PolicyDecisionRequest) return false
        return subject == other.subject &&
            action == other.action &&
            resource == other.resource &&
            context == other.context
    }

    override fun hashCode(): Int {
        var result = subject.hashCode()
        result = 31 * result + action.hashCode()
        result = 31 * result + (resource?.hashCode() ?: 0)
        result = 31 * result + context.hashCode()
        return result
    }

    override fun toString(): String =
        "PolicyDecisionRequest[subject=$subject, action=$action, resource=$resource, context=$context]"

    /**
     * 요청자 속성. JWT claim 에 들어가는 RBAC 정보 + 그 위 ABAC 평가용 추가 속성.
     */
    class Subject(
        tenantId: TenantId,
        userId: UserId,
        roles: Set<String>?,
        permissions: Set<String>?,
        attributes: Map<String, Any?>?,
    ) {

        @get:JvmName("tenantId")
        val tenantId: TenantId = tenantId

        @get:JvmName("userId")
        val userId: UserId = userId

        @get:JvmName("roles")
        val roles: Set<String> =
            if (roles == null) emptySet() else java.util.Set.copyOf(roles)

        @get:JvmName("permissions")
        val permissions: Set<String> =
            if (permissions == null) emptySet() else java.util.Set.copyOf(permissions)

        @get:JvmName("attributes")
        val attributes: Map<String, Any?> =
            if (attributes == null) emptyMap() else java.util.Map.copyOf(TreeMap(attributes))

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Subject) return false
            return tenantId == other.tenantId &&
                userId == other.userId &&
                roles == other.roles &&
                permissions == other.permissions &&
                attributes == other.attributes
        }

        override fun hashCode(): Int {
            var result = tenantId.hashCode()
            result = 31 * result + userId.hashCode()
            result = 31 * result + roles.hashCode()
            result = 31 * result + permissions.hashCode()
            result = 31 * result + attributes.hashCode()
            return result
        }

        override fun toString(): String =
            "Subject[tenantId=$tenantId, userId=$userId, roles=$roles, " +
                "permissions=$permissions, attributes=$attributes]"
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
    class Resource(
        type: String,
        ownerTenant: TenantId?,
        ownerUser: UserId?,
        attributes: Map<String, Any?>?,
    ) {

        @get:JvmName("type")
        val type: String = type

        @get:JvmName("ownerTenant")
        val ownerTenant: TenantId? = ownerTenant

        @get:JvmName("ownerUser")
        val ownerUser: UserId? = ownerUser

        @get:JvmName("attributes")
        val attributes: Map<String, Any?> =
            if (attributes == null) emptyMap() else java.util.Map.copyOf(TreeMap(attributes))

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Resource) return false
            return type == other.type &&
                ownerTenant == other.ownerTenant &&
                ownerUser == other.ownerUser &&
                attributes == other.attributes
        }

        override fun hashCode(): Int {
            var result = type.hashCode()
            result = 31 * result + (ownerTenant?.hashCode() ?: 0)
            result = 31 * result + (ownerUser?.hashCode() ?: 0)
            result = 31 * result + attributes.hashCode()
            return result
        }

        override fun toString(): String =
            "Resource[type=$type, ownerTenant=$ownerTenant, ownerUser=$ownerUser, attributes=$attributes]"
    }
}
