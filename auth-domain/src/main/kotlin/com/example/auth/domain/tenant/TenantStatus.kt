package com.example.auth.domain.tenant

enum class TenantStatus {
    /** 활성. 사용자 신규 가입 / 로그인 모두 허용. */
    ACTIVE,

    /** 일시 정지. 신규 가입 차단 + 로그인 허용 (운영 결정에 따라 차단도 가능). */
    SUSPENDED,

    /** 삭제 예정. 모든 인증 차단 — 토큰 검증 endpoint 에서도 거부. */
    ARCHIVED,
}
