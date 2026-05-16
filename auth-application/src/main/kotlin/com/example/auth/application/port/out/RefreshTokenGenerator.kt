package com.example.auth.application.port.out

/**
 * Refresh token 평문 생성 port. CSPRNG 기반 256bit 이상.
 *
 * application 은 평문을 호출자 (REST 응답) 에 1회 노출하고, 그 직후 hash 만 저장.
 * 평문은 어떤 경로로도 두 번 메모리에 머무르면 안 됩니다.
 */
interface RefreshTokenGenerator {

    /** 평문 token. URL safe base64 권장. */
    fun generate(): String
}
