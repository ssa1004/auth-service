# 세션 revoke / list 권한 정책 (ADR-0016).
#
# RBAC 1차 검증 (PreAuthorize) 통과 후, 다음 조건을 추가로 평가합니다.
#
# 1) 본인 세션은 항상 revoke 가능 (기본).
# 2) 다른 사용자의 세션은 platform_admin 만 revoke 가능 (테넌트 내부).
# 3) cross-tenant 세션은 어떤 admin 도 직접 revoke 불가 — global_admin 만 예외.
#
# OPA decision document 형식: {allow: bool, reasons: [string]}.

package auth.session.revoke

import rego.v1

default allow := false

# 본인 자신의 세션 — 항상 허용.
allow if {
    input.subject.userId == input.resource.ownerUser
    input.subject.tenantId == input.resource.ownerTenant
}

# 같은 테넌트 안에서, platform_admin role 보유자는 다른 사용자의 세션도 revoke 가능.
allow if {
    input.subject.tenantId == input.resource.ownerTenant
    "platform_admin" in input.subject.roles
}

# global_admin 은 cross-tenant 도 허용.
allow if {
    "global_admin" in input.subject.roles
}

# 거부 사유 — fail-closed 시 호출자가 audit / 응답에 사용.
reasons contains "not_resource_owner" if {
    not allow
    input.subject.userId != input.resource.ownerUser
    not "platform_admin" in input.subject.roles
    not "global_admin" in input.subject.roles
}

reasons contains "cross_tenant_access" if {
    not allow
    input.subject.tenantId != input.resource.ownerTenant
    not "global_admin" in input.subject.roles
}
