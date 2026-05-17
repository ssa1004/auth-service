package com.example.auth.adapter.out.security

import com.example.auth.application.port.out.AccessTokenIntrospector
import com.example.auth.application.port.out.AccessTokenIntrospector.Decoded
import java.util.LinkedHashMap
import java.util.Optional
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.stereotype.Component

/**
 * 본 IdP 가 발행한 access JWT 를 디코드 + 서명 검증 + 만료 검사. 같은 `JwkSource` 를
 * 공유하는 [JwtDecoder] 를 위임 — JWK 회전 즉시 새 키도 인식하며 별도 HTTP fetch 가
 * 일어나지 않습니다.
 *
 * 외부 issuer 의 token 은 서명 검증 실패로 [Optional.empty] 반환 — RFC 7662 §2.2
 * 의 "token not found" 와 같은 의미로 introspection 측에서 `active=false` 처리.
 */
@Component
class NimbusAccessTokenIntrospectorAdapter(
    private val jwtDecoder: JwtDecoder,
) : AccessTokenIntrospector {

    override fun decode(token: String): Optional<Decoded> {
        if (token.isBlank()) return Optional.empty()
        return try {
            val jwt = jwtDecoder.decode(token)
            Optional.of(toDecoded(jwt))
        } catch (e: JwtException) {
            // 서명 / 만료 / 형식 오류 — introspection 은 정보 누설을 막기 위해 일관 inactive 처리.
            log.debug("access JWT 디코드 실패 — inactive 로 응답: {}", e.message)
            Optional.empty()
        } catch (e: RuntimeException) {
            log.warn("access JWT 디코드 중 예외 — fail-closed 로 inactive 처리", e)
            Optional.empty()
        }
    }

    private companion object {
        val log = LoggerFactory.getLogger(NimbusAccessTokenIntrospectorAdapter::class.java)

        private val EXCLUDED_KEYS = listOf(
            "iss", "sub", "aud", "exp", "iat", "nbf", "jti",
            "tnt", "roles", "permissions", "amr",
        )

        fun toDecoded(jwt: Jwt): Decoded {
            val additional = LinkedHashMap<String, Any?>(jwt.claims)
            // RFC 7662 표준 응답 필드는 별도 매핑하므로 중복 노출 방지를 위해 제거.
            additional.keys.removeAll(EXCLUDED_KEYS.toSet())
            return Decoded(
                jwt.subject,
                jwt.getClaimAsString("tnt"),
                jwt.issuer?.toString(),
                firstAudience(jwt.audience),
                jwt.id,
                jwt.getClaimAsStringList("roles") ?: emptyList(),
                jwt.getClaimAsStringList("permissions") ?: emptyList(),
                jwt.issuedAt,
                jwt.expiresAt,
                additional,
            )
        }

        fun firstAudience(audience: List<String>?): String? {
            if (audience.isNullOrEmpty()) return null
            return audience[0]
        }
    }
}
