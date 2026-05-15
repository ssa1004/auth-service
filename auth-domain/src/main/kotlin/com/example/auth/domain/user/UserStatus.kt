package com.example.auth.domain.user

enum class UserStatus {
    /** 메일 인증 대기. 로그인 가능하지만 일부 기능 제한 (정책에 따라 차단도 가능). */
    PENDING_VERIFICATION,

    /** 정상. */
    ACTIVE,

    /** 운영자 잠금. 모든 인증 차단. */
    LOCKED,

    /** 사용자 본인 탈퇴. */
    DEACTIVATED,
}
