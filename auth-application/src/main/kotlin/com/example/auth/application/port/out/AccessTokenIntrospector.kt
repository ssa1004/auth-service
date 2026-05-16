package com.example.auth.application.port.out

import java.time.Instant
import java.util.Optional

/**
 * 자체 발행 access JWT 를 디코드 + 서명 검증 + 만료 검사하기 위한 outbound port.
 *
 * 구현체는 `JwtDecoder` 를 감싸 같은 JWKSource 를 공유합니다 — 회전 직후 새 키로
 * 서명된 token 도 즉시 인식. 외부 issuer 의 token 은 [Optional.empty] 로 응답.
 */
interface AccessTokenIntrospector {

    fun decode(token: String): Optional<Decoded>

    /**
     * 디코드된 access JWT 의 핵심 claim 묶음. RFC 7662 응답 매핑에 필요한 필드만.
     */
    @JvmRecord
    data class Decoded(
        val subject: String,
        val tenantId: String?,
        val issuer: String?,
        val audience: String?,
        val jwtId: String?,
        val roles: List<String>,
        val permissions: List<String>,
        val issuedAt: Instant?,
        val expiresAt: Instant?,
        val additionalClaims: Map<String, Any?>,
    )
}
