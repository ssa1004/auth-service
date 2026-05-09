package com.example.auth.adapter.out.security;

import com.example.auth.application.port.out.AccessTokenIntrospector;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

/**
 * 본 IdP 가 발행한 access JWT 를 디코드 + 서명 검증 + 만료 검사. 같은 {@code JwkSource} 를
 * 공유하는 {@link JwtDecoder} 를 위임 — JWK 회전 즉시 새 키도 인식하며 별도 HTTP fetch 가
 * 일어나지 않습니다.
 *
 * <p>외부 issuer 의 token 은 서명 검증 실패로 {@link Optional#empty()} 반환 — RFC 7662 §2.2
 * 의 "token not found" 와 같은 의미로 introspection 측에서 {@code active=false} 처리.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class NimbusAccessTokenIntrospectorAdapter implements AccessTokenIntrospector {

    private final JwtDecoder jwtDecoder;

    @Override
    public Optional<Decoded> decode(String token) {
        if (token == null || token.isBlank()) return Optional.empty();
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return Optional.of(toDecoded(jwt));
        } catch (JwtException e) {
            // 서명 / 만료 / 형식 오류 — introspection 은 정보 누설을 막기 위해 일관 inactive 처리.
            log.debug("access JWT 디코드 실패 — inactive 로 응답: {}", e.getMessage());
            return Optional.empty();
        } catch (RuntimeException e) {
            log.warn("access JWT 디코드 중 예외 — fail-closed 로 inactive 처리", e);
            return Optional.empty();
        }
    }

    private static Decoded toDecoded(Jwt jwt) {
        Map<String, Object> additional = new LinkedHashMap<>(jwt.getClaims());
        // RFC 7662 표준 응답 필드는 별도 매핑하므로 중복 노출 방지를 위해 제거.
        additional.keySet().removeAll(List.of(
                "iss", "sub", "aud", "exp", "iat", "nbf", "jti",
                "tnt", "roles", "permissions", "amr"));
        return new Decoded(
                jwt.getSubject(),
                jwt.getClaimAsString("tnt"),
                jwt.getIssuer() == null ? null : jwt.getIssuer().toString(),
                firstAudience(jwt.getAudience()),
                jwt.getId(),
                jwt.getClaimAsStringList("roles"),
                jwt.getClaimAsStringList("permissions"),
                jwt.getIssuedAt(),
                jwt.getExpiresAt(),
                additional);
    }

    private static String firstAudience(List<String> audience) {
        if (audience == null || audience.isEmpty()) return null;
        return audience.get(0);
    }

    /** 단위 테스트에서 만료된 JWT 의 issuedAt 을 강제로 흘려보낼 때 사용. */
    static Decoded forTest(
            String subject, String tenantId, String issuer, String audience, String jti,
            List<String> roles, List<String> permissions,
            Instant issuedAt, Instant expiresAt) {
        return new Decoded(subject, tenantId, issuer, audience, jti,
                roles, permissions, issuedAt, expiresAt, Map.of());
    }
}
