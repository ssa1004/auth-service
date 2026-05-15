package com.example.auth.domain.audit

enum class AuditEventType {
    USER_REGISTERED,
    LOGIN_SUCCEEDED,
    LOGIN_FAILED_BAD_CREDENTIALS,
    LOGIN_FAILED_USER_LOCKED,
    LOGIN_FAILED_RATE_LIMITED,
    MFA_REQUIRED,
    MFA_VERIFIED,
    MFA_FAILED,
    MFA_ENABLED,
    MFA_DISABLED,
    REFRESH_ROTATED,
    REFRESH_REUSE_DETECTED,
    SESSION_REVOKED_BY_USER,
    SESSION_REVOKED_BY_REUSE,
    ROLE_ASSIGNED,
    ROLE_REVOKED,

    /** ABAC 정책이 행위를 허용한 결정 — Decision log (ADR-0016). */
    POLICY_DECISION_ALLOW,

    /** ABAC 정책이 행위를 거부한 결정 — Decision log (ADR-0016). */
    POLICY_DECISION_DENY,

    /** RFC 7662 introspect 호출 — active 여부만 기록 (ADR-0017). */
    TOKEN_INTROSPECTED,

    /** 운영자가 RFC 7009 revoke endpoint 로 사용자의 토큰을 강제 revoke (ADR-0018). */
    TOKEN_REVOKED_BY_ADMIN,
}
