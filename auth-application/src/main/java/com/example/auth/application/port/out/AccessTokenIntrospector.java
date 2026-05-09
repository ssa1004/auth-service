package com.example.auth.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 자체 발행 access JWT 를 디코드 + 서명 검증 + 만료 검사하기 위한 outbound port.
 *
 * <p>구현체는 {@code JwtDecoder} 를 감싸 같은 JWKSource 를 공유합니다 — 회전 직후 새 키로
 * 서명된 token 도 즉시 인식. 외부 issuer 의 token 은 {@link Optional#empty()} 로 응답.
 */
public interface AccessTokenIntrospector {

    Optional<Decoded> decode(String token);

    /**
     * 디코드된 access JWT 의 핵심 claim 묶음. RFC 7662 응답 매핑에 필요한 필드만.
     */
    record Decoded(
            String subject,
            String tenantId,
            String issuer,
            String audience,
            String jwtId,
            List<String> roles,
            List<String> permissions,
            Instant issuedAt,
            Instant expiresAt,
            Map<String, Object> additionalClaims) {
    }
}
