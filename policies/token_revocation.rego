# RFC 7009 Token Revocation 의 admin 권한 정책 (ADR-0018).
#
# 본 IdP 의 일반 사용자는 자기 세션 revoke 를 RevokeSessionUseCase 로 직접 수행합니다.
# /oauth2/revoke 는 *운영자 / 보안 콘솔* 이 다른 사용자의 토큰을 강제 종료하는 경로이므로
# 호출 client 가 token.revoke scope 를 가지고 있어야 통과합니다.
#
# 입력:
#   subject.attributes.clientId : 호출 client_id (RFC 6749 의 client_credentials 인증 결과)
#   subject.attributes.scopes   : 호출 client 의 scope 집합
#   action                       : "token.revoke"
#   context.ip                   : 호출자 IP (감사용)
#
# 입력 경로가 attributes.* 인 이유: 본 정책의 호출자는 *user* 가 아니라 *client* 라
# subject.tenantId / userId 가 비어있고, RBAC role / permission 도 무관합니다. client 의
# scope / id 같은 client-level 속성은 PolicyDecisionRequest.Subject.attributes 에 담겨
# 들어옵니다 (다른 정책의 attributes.roleSlug 등과 같은 관례).
#
# 출력 (OPA 표준): {allow: bool, reasons: [string]}
# 본 정책의 fail-closed: 정책 평가 실패 = deny. 호출자가 audit 로 사유를 기록합니다.

package auth.token.revoke

import rego.v1

default allow := false

# admin scope 보유 시 허용. 운영에서는 별도 admin client 를 RegisteredClient 에 등록하고
# 본 scope 만 부여 — 일반 service client 는 자체 scope (api.read 등) 만 가집니다.
allow if {
    "token.revoke" in input.subject.attributes.scopes
    has_client_id
}

has_client_id if {
    input.subject.attributes.clientId
    input.subject.attributes.clientId != ""
}

# 거부 사유 — fail-closed 시 호출자가 audit / 모니터링에 사용.
reasons contains "missing_token_revoke_scope" if {
    not allow
    not "token.revoke" in input.subject.attributes.scopes
}

reasons contains "missing_client_id" if {
    not allow
    not has_client_id
}
