package com.example.auth.application.port.in;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * RFC 7662 Token Introspection 진입점.
 *
 * <p>Resource Server 가 access token 또는 refresh token 의 유효성을 본 IdP 에 직접 묻기
 * 위한 inbound port. 자체 JWT 검증으로는 발급 후 강제 revoke 된 token 이 TTL 만료 전까지
 * 그대로 통과하므로, 즉시 차단이 필요한 시나리오 (사용자 정지, 계정 탈취 대응) 에서
 * introspection 호출이 정답입니다.
 *
 * <p>본 IdP 는 *우리가 발행한 token 만* 처리합니다. 외부에서 가짜 / 다른 issuer 의 access
 * token 을 introspect 시도하면 RFC 7662 §2.2 에 따라 정보 누설 없이
 * {@code {"active":false}} 만 반환합니다.
 */
public interface IntrospectTokenUseCase {

    Result introspect(Command cmd);

    /**
     * @param token         introspect 할 토큰 평문. access JWT 또는 refresh token.
     * @param tokenTypeHint RFC 7662 의 권장 hint. 본 구현은 hint 없이도 두 형식 모두 시도하므로
     *                      참고용 (audit 에 기록).
     * @param callerClient  introspect 호출한 client_id. audit 와 이상 행위 모니터링용.
     */
    record Command(String token, String tokenTypeHint, String callerClient) {
        public Command {
            Objects.requireNonNull(token, "token");
            if (token.isBlank()) {
                throw new IllegalArgumentException("token 은 비어있을 수 없습니다");
            }
        }
    }

    /**
     * RFC 7662 §2.2 응답 모델. {@code active=false} 인 경우 다른 필드는 모두 null.
     */
    record Result(
            boolean active,
            String tokenType,
            String scope,
            String clientId,
            String username,
            String subject,
            String tenantId,
            List<String> roles,
            Instant issuedAt,
            Instant expiresAt,
            Instant notBefore,
            String issuer,
            String jwtId,
            Map<String, Object> additional) {

        public static Result inactive() {
            return new Result(false, null, null, null, null, null, null,
                    List.of(), null, null, null, null, null, Map.of());
        }
    }
}
