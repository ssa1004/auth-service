package com.example.auth.application.service

import com.example.auth.application.port.`in`.AuditLoginAttemptsUseCase
import com.example.auth.application.port.`in`.IntrospectTokenUseCase
import com.example.auth.application.port.out.AccessTokenBlocklist
import com.example.auth.application.port.out.AccessTokenIntrospector
import com.example.auth.application.port.out.RefreshTokenRepository
import com.example.auth.domain.audit.AuditEventType
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import com.example.auth.domain.token.RefreshTokenStatus
import com.example.auth.domain.token.TokenHasher
import java.time.Clock
import java.util.Optional
import java.util.UUID
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

/**
 * RFC 7662 Token Introspection 구현 (ADR-0017).
 *
 * 처리 순서:
 * 1. token_type_hint 가 있으면 그 형식부터 시도 — 빠른 경로.
 * 2. access JWT 디코드 (서명 / 만료 검증) → 성공 시 jti 가 blocklist 에 있는지 확인.
 * 3. JWT 가 아니라면 refresh token 으로 가정하여 hash → DB 조회. ACTIVE 만 active=true.
 * 4. 두 형식 모두 실패하면 RFC 7662 §2.2 에 따라 `{"active":false}` — 정보 누설 X.
 *
 * 본 service 는 audit 에 introspect 결과 (active 여부 + 호출 client) 만 기록합니다 —
 * 토큰 평문 / 사용자 PII 는 적재하지 않습니다 (ISMS-P 적합성).
 */
@Service
class IntrospectTokenService(
    private val accessTokenIntrospector: AccessTokenIntrospector,
    private val accessTokenBlocklist: AccessTokenBlocklist,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val auditUseCase: AuditLoginAttemptsUseCase,
    private val clock: Clock,
) : IntrospectTokenUseCase {

    @Transactional(readOnly = true)
    override fun introspect(cmd: IntrospectTokenUseCase.Command): IntrospectTokenUseCase.Result {
        val result = lookup(cmd)
        recordAudit(cmd, result)
        return result
    }

    private fun lookup(cmd: IntrospectTokenUseCase.Command): IntrospectTokenUseCase.Result {
        // hint 가 refresh 면 refresh 부터, 그 외는 access 부터.
        return if (HINT_REFRESH == cmd.tokenTypeHint) {
            introspectRefresh(cmd.token)
                .or { introspectAccess(cmd.token) }
                .orElse(IntrospectTokenUseCase.Result.inactive())
        } else {
            introspectAccess(cmd.token)
                .or { introspectRefresh(cmd.token) }
                .orElse(IntrospectTokenUseCase.Result.inactive())
        }
    }

    private fun introspectAccess(token: String): Optional<IntrospectTokenUseCase.Result> {
        val decoded = accessTokenIntrospector.decode(token)
        if (decoded.isEmpty) return Optional.empty()
        val d = decoded.get()
        val now = clock.instant()
        // 만료 / nbf 는 decoder 가 검증하지만 introspect 는 명시적으로 한 번 더 확인.
        if (d.expiresAt != null && !now.isBefore(d.expiresAt)) {
            return Optional.of(IntrospectTokenUseCase.Result.inactive())
        }
        if (d.jwtId != null && accessTokenBlocklist.contains(d.jwtId)) {
            // 운영자 강제 revoke (RFC 7009) 결과가 즉시 반영되는 지점.
            return Optional.of(IntrospectTokenUseCase.Result.inactive())
        }
        return Optional.of(
            IntrospectTokenUseCase.Result(
                true,
                TOKEN_TYPE_BEARER,
                joinScope(d.permissions),
                d.audience,
                null,
                d.subject,
                d.tenantId,
                d.roles,
                d.issuedAt,
                d.expiresAt,
                d.issuedAt,
                d.issuer,
                d.jwtId,
                emptyMap(),
            ),
        )
    }

    private fun introspectRefresh(token: String): Optional<IntrospectTokenUseCase.Result> {
        // refresh token 은 평문 형태가 자유롭지만, JWT 처럼 dot 두 개로 시작하면 access 일
        // 가능성이 더 높으므로 굳이 hash 조회까지 가지 않게 단축.
        if (looksLikeJwt(token)) return Optional.empty()
        val hash = TokenHasher.sha256(token)
        val found = refreshTokenRepository.findByTokenHashReadOnly(hash)
        if (found.isEmpty) return Optional.empty()
        val rt = found.get()
        val now = clock.instant()
        val active = rt.status == RefreshTokenStatus.ACTIVE && now.isBefore(rt.expiresAt)
        if (!active) {
            return Optional.of(IntrospectTokenUseCase.Result.inactive())
        }
        return Optional.of(
            IntrospectTokenUseCase.Result(
                true,
                "refresh",
                null,
                null,
                null,
                rt.userId.asString(),
                rt.tenantId.asString(),
                emptyList(),
                rt.issuedAt,
                rt.expiresAt,
                rt.issuedAt,
                null,
                rt.id.toString(),
                emptyMap(),
            ),
        )
    }

    private fun recordAudit(cmd: IntrospectTokenUseCase.Command, result: IntrospectTokenUseCase.Result) {
        try {
            // active 여부와 token type / 호출자만 audit. 토큰 자체는 절대 적재 X.
            val payload = LinkedHashMap<String, String>()
            payload["active"] = result.active.toString()
            if (result.tokenType != null) payload["tokenType"] = result.tokenType
            if (cmd.tokenTypeHint != null) payload["hint"] = cmd.tokenTypeHint
            if (cmd.callerClient != null) payload["client"] = cmd.callerClient
            // active 면 누구의 토큰인지 audit 에는 남겨야 운영자가 이상 패턴 (특정 사용자에
            // 대한 introspect 폭증) 을 잡을 수 있음. inactive (가짜 토큰 / 외부 issuer) 은
            // 사용자 컨텍스트가 없으므로 nil UUID 로 표현.
            val tenant = if (result.tenantId != null) TenantId.of(result.tenantId) else TenantId.of(NIL_UUID)
            val user: UserId? = if (result.subject != null) UserId.of(result.subject) else null
            auditUseCase.record(
                tenant, user, AuditEventType.TOKEN_INTROSPECTED,
                null, null, payload,
            )
        } catch (e: RuntimeException) {
            // audit 실패가 introspection 응답을 막으면 안 됨.
            log.warn("token introspect audit 적재 실패 — 결과는 정상 반환", e)
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(IntrospectTokenService::class.java)

        private const val TOKEN_TYPE_BEARER = "Bearer"
        private const val HINT_REFRESH = "refresh_token"

        /** RFC 4122 의 nil UUID — "사용자 컨텍스트 없음" 을 audit 에 표현. */
        private val NIL_UUID = UUID(0L, 0L)

        private fun looksLikeJwt(token: String): Boolean {
            // 가장 단순한 휴리스틱 — JWT 는 base64url . base64url . base64url 형식.
            val firstDot = token.indexOf('.')
            if (firstDot <= 0) return false
            val secondDot = token.indexOf('.', firstDot + 1)
            return secondDot > firstDot
        }

        private fun joinScope(permissions: List<String>?): String? {
            if (permissions == null || permissions.isEmpty()) return null
            return permissions.joinToString(" ")
        }
    }
}
