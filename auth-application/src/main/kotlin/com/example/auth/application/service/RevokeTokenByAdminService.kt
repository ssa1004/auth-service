package com.example.auth.application.service

import com.example.auth.application.authz.PolicyDecisionRequest
import com.example.auth.application.authz.PolicyDecisionService
import com.example.auth.application.exception.PolicyDeniedException
import com.example.auth.application.port.`in`.AuditLoginAttemptsUseCase
import com.example.auth.application.port.`in`.RevokeTokenByAdminUseCase
import com.example.auth.application.port.out.AccessTokenBlocklist
import com.example.auth.application.port.out.AccessTokenIntrospector
import com.example.auth.application.port.out.RefreshTokenRepository
import com.example.auth.domain.audit.AuditEventType
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import com.example.auth.domain.token.RefreshToken
import com.example.auth.domain.token.RefreshTokenStatus
import com.example.auth.domain.token.TokenHasher
import java.time.Clock
import java.time.Duration
import java.util.Optional
import java.util.UUID
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

/**
 * RFC 7009 Token Revocation 구현 (ADR-0018).
 *
 * 호출 흐름:
 * 1. OPA 정책 `auth/token/revoke` 평가 — 호출 client 가 `token.revoke`
 *    scope 보유 여부 확인. 거부 시 PolicyDenied → 403.
 * 2. token_type_hint 가 access_token 이면 JWT 디코드 → jti 를 Redis 블록리스트에
 *    잔여 유효시간 TTL 로 추가. introspection 호출 즉시 active=false 응답.
 * 3. token_type_hint 가 refresh_token 이면 hash 로 lookup → REVOKED_BY_ADMIN 마킹.
 * 4. hint 가 없으면 access → refresh 순으로 시도. 둘 다 실패해도 RFC 7009 §2.2 에
 *    따라 호출자에게는 200 만 반환 (정보 누설 차단).
 * 5. 모든 결과를 audit 에 `TOKEN_REVOKED_BY_ADMIN` 로 기록.
 *
 * 본 service 자체는 HTTP 응답 형식과 무관 — controller 가 항상 200 응답을 보장합니다.
 */
@Service
class RevokeTokenByAdminService(
    private val accessTokenIntrospector: AccessTokenIntrospector,
    private val accessTokenBlocklist: AccessTokenBlocklist,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val policyDecisionService: PolicyDecisionService,
    private val auditUseCase: AuditLoginAttemptsUseCase,
    private val clock: Clock,
) : RevokeTokenByAdminUseCase {

    @Transactional
    override fun revoke(cmd: RevokeTokenByAdminUseCase.Command) {
        val outcome = doRevoke(cmd)
        recordAudit(cmd, outcome)
    }

    private fun doRevoke(cmd: RevokeTokenByAdminUseCase.Command): Outcome {
        // 1) OPA gate — admin scope 검증. 거부 시 PolicyDenied 가 throw.
        evaluatePolicy(cmd)

        // 2) hint 따라 우선 형식 결정. 첫 번째 시도에서 실패 시 다른 형식으로 fallback.
        val refreshFirst = HINT_REFRESH == cmd.tokenTypeHint
        if (refreshFirst) {
            val refreshOutcome = revokeRefresh(cmd.token)
            if (refreshOutcome.isPresent) return refreshOutcome.get()
            return revokeAccess(cmd.token).orElseGet { Outcome.unknown() }
        }
        val accessOutcome = revokeAccess(cmd.token)
        if (accessOutcome.isPresent) return accessOutcome.get()
        return revokeRefresh(cmd.token).orElseGet { Outcome.unknown() }
    }

    private fun evaluatePolicy(cmd: RevokeTokenByAdminUseCase.Command) {
        // 호출자는 client_credentials 의 client — 사용자 컨텍스트가 없으므로 nil UUID 로
        // PolicyDecisionRequest 의 non-null 가드를 통과시키고, OPA 정책은 attributes 의
        // clientId / scopes 만 보고 결정합니다.
        val nilTenant = TenantId.of(NIL_UUID)
        val nilUser = UserId.of(NIL_UUID)
        val request = PolicyDecisionRequest(
            PolicyDecisionRequest.Subject(
                nilTenant, nilUser,
                emptySet(), emptySet(),
                mapOf(
                    "clientId" to (cmd.callerClient ?: ""),
                    "scopes" to cmd.callerScopes,
                ),
            ),
            "token.revoke",
            PolicyDecisionRequest.Resource(
                "token", nilTenant, null, emptyMap(),
            ),
            if (cmd.ipAddress == null) emptyMap() else mapOf("ip" to cmd.ipAddress),
        )
        val decision = policyDecisionService.evaluate("auth/token/revoke", request)
        if (!decision.allow) {
            throw PolicyDeniedException(decision.reasons)
        }
    }

    private fun revokeAccess(token: String): Optional<Outcome> {
        val decoded = accessTokenIntrospector.decode(token)
        if (decoded.isEmpty) return Optional.empty()
        val d = decoded.get()
        val now = clock.instant()
        if (d.expiresAt != null) {
            val remaining = Duration.between(now, d.expiresAt)
            if (remaining.isNegative || remaining.isZero) {
                // 이미 만료된 access — 적재할 필요 없음. 호출자 시각에서는 revoke 성공으로 간주.
                return Optional.of(Outcome.access(d, Duration.ZERO))
            }
            accessTokenBlocklist.add(d.jwtId!!, remaining)
            return Optional.of(Outcome.access(d, remaining))
        }
        // exp 없는 비정상 토큰 — 안전을 위해 한 시간 임의 TTL 로 차단.
        accessTokenBlocklist.add(d.jwtId!!, Duration.ofHours(1))
        return Optional.of(Outcome.access(d, Duration.ofHours(1)))
    }

    private fun revokeRefresh(token: String): Optional<Outcome> {
        if (looksLikeJwt(token)) return Optional.empty()
        val hash = TokenHasher.sha256(token)
        val found: Optional<RefreshToken> = refreshTokenRepository.findByTokenHashReadOnly(hash)
        if (found.isEmpty) return Optional.empty()
        val rt = found.get()
        // 이미 종료된 토큰도 RFC 7009 §2.2 에 따라 200. 그러나 다시 마킹할 필요는 없음.
        if (rt.status != RefreshTokenStatus.ACTIVE) {
            return Optional.of(Outcome.refresh(rt, false))
        }
        refreshTokenRepository.save(rt.markRevokedByAdmin(clock.instant()))
        return Optional.of(Outcome.refresh(rt, true))
    }

    private fun recordAudit(cmd: RevokeTokenByAdminUseCase.Command, outcome: Outcome) {
        try {
            val payload = LinkedHashMap<String, String>()
            payload["result"] = outcome.kind
            cmd.tokenTypeHint?.let { payload["hint"] = it }
            cmd.callerClient?.let { payload["client"] = it }
            if (outcome.jti != null) payload["jti"] = outcome.jti
            if (outcome.sessionId != null) payload["sessionId"] = outcome.sessionId
            if (outcome.blocklistTtlSeconds >= 0) {
                payload["blocklistTtlSeconds"] = outcome.blocklistTtlSeconds.toString()
            }
            // tenantId 는 audit 의 non-null 가드 충족용. unknown 결과는 nil UUID 로 기록.
            val tenant = outcome.tenantId ?: TenantId.of(NIL_UUID)
            auditUseCase.record(
                tenant, outcome.userId,
                AuditEventType.TOKEN_REVOKED_BY_ADMIN,
                cmd.ipAddress, null, payload,
            )
        } catch (e: RuntimeException) {
            log.warn("admin token revoke audit 적재 실패", e)
        }
    }

    /** 결과 묶음 — audit 기록을 위한 내부 구조. */
    @JvmRecord
    private data class Outcome(
        val kind: String,
        val tenantId: TenantId?,
        val userId: UserId?,
        val jti: String?,
        val sessionId: String?,
        val blocklistTtlSeconds: Long,
    ) {
        companion object {
            fun unknown(): Outcome = Outcome("unknown", null, null, null, null, -1)

            fun access(d: AccessTokenIntrospector.Decoded, ttl: Duration?): Outcome = Outcome(
                "access",
                if (d.tenantId != null) TenantId.of(d.tenantId) else null,
                if (d.subject != null) UserId.of(d.subject) else null,
                d.jwtId, null,
                ttl?.toSeconds() ?: -1,
            )

            fun refresh(rt: RefreshToken, newlyRevoked: Boolean): Outcome = Outcome(
                if (newlyRevoked) "refresh" else "refresh_already_inactive",
                rt.tenantId, rt.userId, null, rt.id.toString(), -1,
            )
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(RevokeTokenByAdminService::class.java)

        private const val HINT_REFRESH = "refresh_token"

        /** RFC 4122 의 nil UUID — "사용자 컨텍스트 없음" 을 표현하는 sentinel. */
        private val NIL_UUID = UUID(0L, 0L)

        private fun looksLikeJwt(token: String): Boolean {
            val firstDot = token.indexOf('.')
            if (firstDot <= 0) return false
            val secondDot = token.indexOf('.', firstDot + 1)
            return secondDot > firstDot
        }
    }
}
