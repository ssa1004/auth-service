package com.example.auth.domain.token

enum class RefreshTokenStatus {
    /** 발급되어 사용 가능한 상태. */
    ACTIVE,

    /** 정상 회전으로 종료. parent 를 가리키는 후속 토큰이 존재. */
    REVOKED_ROTATED,

    /** 사용자가 *내 세션 목록* 에서 직접 revoke. */
    REVOKED_BY_USER,

    /** 운영자가 RFC 7009 revoke endpoint 로 강제 revoke (ADR-0018). */
    REVOKED_BY_ADMIN,

    /** 이미 회전된 토큰이 다시 들어와 탈취 의심으로 강제 revoke 된 상태. */
    REVOKED_REUSE_DETECTED,

    /** 만료. 정기 정리 작업이 status 를 EXPIRED 로 마킹할 수도 있음 (현재 사용은 선택). */
    EXPIRED,
}
