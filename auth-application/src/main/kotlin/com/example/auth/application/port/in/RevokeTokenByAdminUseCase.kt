package com.example.auth.application.port.`in`

/**
 * RFC 7009 Token Revocation 진입점 — 운영자가 사용자의 access JWT 또는 refresh token 을
 * 즉시 강제 종료 (ADR-0018).
 *
 * 사용자 자신의 세션 revoke 는 `RevokeSessionUseCase` (내 세션 목록에서 직접) 가
 * 담당합니다. 본 use case 는 admin scope 를 가진 client 만 호출 가능 — OPA 정책
 * `policies/token_revocation.rego` 가 client 의 scope / id 를 검증.
 *
 * RFC 7009 §2.2 — *어떤* token 을 받든 응답은 항상 200. 알 수 없거나 이미 만료된 token
 * 도 200. 정보 누설 차단이 표준의 핵심 의도.
 */
interface RevokeTokenByAdminUseCase {

    fun revoke(cmd: Command)

    /**
     * 방어적 복사 + 검증이 있어 일반 `class` + `@get:JvmName` 으로 record-style accessor 호환.
     *
     * @param token         revoke 대상 토큰 (access JWT 또는 refresh token).
     * @param tokenTypeHint RFC 7009 의 권장 hint — access_token / refresh_token. 없으면
     *                      두 형식을 차례대로 시도.
     * @param callerClient  호출한 client_id. OPA 정책 입력 + audit 기록.
     * @param callerScopes  호출 client 의 scope 집합. `token.revoke` 가 핵심.
     * @param ipAddress     호출자 IP. audit / OPA context 에 사용.
     */
    class Command(
        token: String,
        tokenTypeHint: String?,
        callerClient: String?,
        callerScopes: Set<String>?,
        ipAddress: String?,
    ) {

        @get:JvmName("token")
        val token: String = token

        @get:JvmName("tokenTypeHint")
        val tokenTypeHint: String? = tokenTypeHint

        @get:JvmName("callerClient")
        val callerClient: String? = callerClient

        @get:JvmName("callerScopes")
        val callerScopes: Set<String> =
            if (callerScopes == null) emptySet() else java.util.Set.copyOf(callerScopes)

        @get:JvmName("ipAddress")
        val ipAddress: String? = ipAddress

        init {
            require(token.isNotBlank()) { "token 은 비어있을 수 없습니다" }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Command) return false
            return token == other.token &&
                tokenTypeHint == other.tokenTypeHint &&
                callerClient == other.callerClient &&
                callerScopes == other.callerScopes &&
                ipAddress == other.ipAddress
        }

        override fun hashCode(): Int {
            var result = token.hashCode()
            result = 31 * result + (tokenTypeHint?.hashCode() ?: 0)
            result = 31 * result + (callerClient?.hashCode() ?: 0)
            result = 31 * result + callerScopes.hashCode()
            result = 31 * result + (ipAddress?.hashCode() ?: 0)
            return result
        }

        override fun toString(): String =
            "Command[token=$token, tokenTypeHint=$tokenTypeHint, callerClient=$callerClient, " +
                "callerScopes=$callerScopes, ipAddress=$ipAddress]"
    }
}
