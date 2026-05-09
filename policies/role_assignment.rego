# Role 부여 정책 (ADR-0016).
#
# 운영 사고를 막기 위한 escalation 정책 — 일반 admin 이 다른 사용자에게 admin 권한을
# 부여하지 못하도록 차단. admin 권한 부여는 senior_admin 보유자만 가능.
#
# 일반 role (billing-operator 등) 은 platform_admin 도 부여 가능.

package auth.role.assign

import rego.v1

default allow := false

# 같은 테넌트 안 + 일반 role + platform_admin → 허용.
allow if {
    input.subject.tenantId == input.resource.ownerTenant
    "platform_admin" in input.subject.roles
    not is_admin_role(input.resource.attributes.roleSlug)
}

# admin role 부여는 senior_admin 만.
allow if {
    input.subject.tenantId == input.resource.ownerTenant
    "senior_admin" in input.subject.roles
    is_admin_role(input.resource.attributes.roleSlug)
}

# global_admin 은 어떤 role 이든 어떤 테넌트에든 부여 가능.
allow if {
    "global_admin" in input.subject.roles
}

is_admin_role(slug) if {
    startswith(slug, "platform_admin")
}

is_admin_role(slug) if {
    startswith(slug, "senior_admin")
}

is_admin_role(slug) if {
    slug == "global_admin"
}

reasons contains "tenant_mismatch" if {
    not allow
    input.subject.tenantId != input.resource.ownerTenant
    not "global_admin" in input.subject.roles
}

reasons contains "admin_role_requires_senior_admin" if {
    not allow
    is_admin_role(input.resource.attributes.roleSlug)
    not "senior_admin" in input.subject.roles
    not "global_admin" in input.subject.roles
}

reasons contains "missing_platform_admin" if {
    not allow
    not is_admin_role(input.resource.attributes.roleSlug)
    not "platform_admin" in input.subject.roles
    not "global_admin" in input.subject.roles
}
