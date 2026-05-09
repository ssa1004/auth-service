# 테넌트 격리 정책 (ADR-0006 의 데이터 격리 + ADR-0016 의 ABAC).
#
# 모든 API 호출에서 *호출자의 테넌트* 와 *리소스 소유 테넌트* 가 같아야 합니다.
# 단 한 가지 예외: global_admin role 보유자가 운영 작업 수행 시.
#
# 본 정책은 cross-cutting — 다른 정책에서 import 하여 재사용할 수 있도록 분리했습니다.

package auth.tenant.isolation

import rego.v1

default allow := false

# 같은 테넌트 — 통과.
allow if {
    input.subject.tenantId == input.resource.ownerTenant
}

# global_admin — 모든 테넌트 접근 가능. 운영 / 컴플라이언스 / 데이터 마이그레이션.
allow if {
    "global_admin" in input.subject.roles
}

reasons contains "tenant_mismatch" if {
    not allow
    input.subject.tenantId != input.resource.ownerTenant
    not "global_admin" in input.subject.roles
}
