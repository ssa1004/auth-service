package com.example.auth.application.port.in;

import java.util.Objects;
import java.util.Set;

/**
 * RFC 7009 Token Revocation 진입점 — 운영자가 사용자의 access JWT 또는 refresh token 을
 * 즉시 강제 종료 (ADR-0018).
 *
 * <p>사용자 자신의 세션 revoke 는 {@code RevokeSessionUseCase} (내 세션 목록에서 직접) 가
 * 담당합니다. 본 use case 는 admin scope 를 가진 client 만 호출 가능 — OPA 정책
 * {@code policies/token_revocation.rego} 가 client 의 scope / id 를 검증.
 *
 * <p>RFC 7009 §2.2 — *어떤* token 을 받든 응답은 항상 200. 알 수 없거나 이미 만료된 token
 * 도 200. 정보 누설 차단이 표준의 핵심 의도.
 */
public interface RevokeTokenByAdminUseCase {

    void revoke(Command cmd);

    /**
     * @param token         revoke 대상 토큰 (access JWT 또는 refresh token).
     * @param tokenTypeHint RFC 7009 의 권장 hint — access_token / refresh_token. 없으면
     *                      두 형식을 차례대로 시도.
     * @param callerClient  호출한 client_id. OPA 정책 입력 + audit 기록.
     * @param callerScopes  호출 client 의 scope 집합. {@code token.revoke} 가 핵심.
     * @param ipAddress     호출자 IP. audit / OPA context 에 사용.
     */
    record Command(
            String token,
            String tokenTypeHint,
            String callerClient,
            Set<String> callerScopes,
            String ipAddress) {

        public Command {
            Objects.requireNonNull(token, "token");
            if (token.isBlank()) {
                throw new IllegalArgumentException("token 은 비어있을 수 없습니다");
            }
            callerScopes = callerScopes == null ? Set.of() : Set.copyOf(callerScopes);
        }
    }
}
