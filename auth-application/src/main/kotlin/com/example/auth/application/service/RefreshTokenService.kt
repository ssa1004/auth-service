package com.example.auth.application.service

import com.example.auth.application.exception.InvalidCredentialsException
import com.example.auth.application.exception.RateLimitedException
import com.example.auth.application.exception.RefreshReuseDetectedException
import com.example.auth.application.port.`in`.AuditLoginAttemptsUseCase
import com.example.auth.application.port.`in`.RefreshTokenUseCase
import com.example.auth.application.port.out.RateLimiter
import com.example.auth.application.port.out.RefreshTokenRepository
import com.example.auth.application.port.out.TenantRepository
import com.example.auth.application.port.out.UserRepository
import com.example.auth.application.security.AuthProperties
import com.example.auth.application.security.AuthTokens
import com.example.auth.domain.audit.AuditEventType
import com.example.auth.domain.token.TokenHasher
import java.time.Clock
import java.time.Duration
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

/**
 * Refresh token rotation + reuse detection (ADR-0004).
 *
 * 1. 요청된 평문 token 을 hash → DB lookup
 * 2. 찾은 토큰이 ACTIVE 면 → 회전 발급 (parent 로 연결)
 * 3. 찾은 토큰이 ROTATED 면 → reuse 신호. 사용자의 모든 refresh 일괄 revoke + 401
 * 4. 그 외 (REVOKED_BY_USER / EXPIRED 등) → 401
 */
@Service
class RefreshTokenService(
    private val refreshTokenRepository: RefreshTokenRepository,
    private val userRepository: UserRepository,
    private val tenantRepository: TenantRepository,
    private val sessionIssuer: SessionIssuer,
    private val rateLimiter: RateLimiter,
    private val auditUseCase: AuditLoginAttemptsUseCase,
    private val authProperties: AuthProperties,
    private val clock: Clock,
) : RefreshTokenUseCase {

    /**
     * reuse detection 시 throw 하기 *전에* 일괄 revoke 까지 커밋되어야 합니다.
     * RuntimeException 은 기본적으로 트랜잭션 rollback 을 트리거하므로, 본 예외만은 명시적
     * 으로 commit 하도록 noRollbackFor 지정. (audit 자체는 REQUIRES_NEW 로 별도 보장)
     */
    @Transactional(noRollbackFor = [RefreshReuseDetectedException::class])
    override fun refresh(cmd: RefreshTokenUseCase.Command): AuthTokens {
        // OWASP API4 — refresh 는 인증 없이 호출되므로 IP 별 token bucket 으로
        // brute-force 토큰 추측 / DoS 시도를 차단. 정상 client 의 rotation 간격은 분 단위라
        // login 과 같은 bucket 설정 (10 req/min) 안에 충분히 들어옵니다. ip 가 null 인 단위
        // 테스트 경로는 우회 — e2e / 운영은 ClientIpResolver 가 항상 채움.
        if (cmd.ipAddress != null) {
            val rateKey = "refresh:${cmd.ipAddress}"
            if (!rateLimiter.tryConsume(rateKey)) {
                throw RateLimitedException()
            }
        }
        val hash = TokenHasher.sha256(cmd.refreshTokenPlain)
        val existing = refreshTokenRepository.findByTokenHash(hash)
            .orElseThrow { InvalidCredentialsException() }

        if (existing.isReuseSignal()) {
            // 이미 정상 회전된 token 이 다시 들어왔습니다. 대부분 탈취 신호지만, 모바일 client 의
            // 네트워크 jitter / 백그라운드 retry 로 같은 refresh 를 회전 직후 한 번 더 보내는
            // 정당한 케이스가 있습니다. grace 윈도우 안 + 같은 IP 면 revoke 까지 가지 않고 401 만.
            val sameNetwork = existing.ipAddress == cmd.ipAddress
            if (existing.isWithinReuseGrace(
                    clock.instant(), authProperties.refreshReuseGracePeriod, sameNetwork,
                )
            ) {
                log.info(
                    "refresh grace retry user={} sinceRotation={}s — 401 만 반환, revoke 하지 않음",
                    existing.userId.asString(),
                    Duration.between(existing.lastUsedAt!!, clock.instant()).toSeconds(),
                )
                // grace 처리 — invalid credential 응답만. 정상 client 는 자기가 받은 새 refresh 로 재시도하면 됨.
                throw InvalidCredentialsException()
            }
            // 진짜 reuse — 일괄 revoke (ADR-0004).
            val revoked = refreshTokenRepository.revokeAllForUser(existing.tenantId, existing.userId)
            auditUseCase.record(
                existing.tenantId, existing.userId,
                AuditEventType.REFRESH_REUSE_DETECTED,
                cmd.ipAddress, cmd.userAgent,
                mapOf("revokedSessions" to revoked.toString()),
            )
            log.warn(
                "refresh reuse detected user={} revoked={}",
                existing.userId.asString(), revoked,
            )
            throw RefreshReuseDetectedException()
        }

        if (!existing.isUsable(clock.instant())) {
            // EXPIRED / REVOKED_BY_USER / REVOKED_REUSE_DETECTED — 모두 invalid 처리.
            throw InvalidCredentialsException()
        }

        val tenant = tenantRepository.findById(existing.tenantId)
            .orElseThrow { InvalidCredentialsException() }
        val user = userRepository.findById(tenant.id, existing.userId)
            .orElseThrow { InvalidCredentialsException() }
        if (!user.canLogin()) {
            throw InvalidCredentialsException()
        }

        // 1) 기존 token 을 ROTATED 로 마킹 (재사용 시 이게 reuse signal 로 잡힘)
        refreshTokenRepository.save(existing.markRotated(clock.instant()))
        // 2) 새 access + refresh 발급. parent = existing.id 로 연결 (audit 추적용).
        val amr: Set<String> = if (user.requiresMfa()) setOf("pwd", "mfa") else setOf("pwd")
        val tokens = sessionIssuer.issue(
            tenant, user, amr,
            cmd.ipAddress, cmd.userAgent, existing.deviceLabel,
            existing.id,
        )
        auditUseCase.record(
            tenant.id, user.id, AuditEventType.REFRESH_ROTATED,
            cmd.ipAddress, cmd.userAgent,
            mapOf("parentSession" to existing.id.toString()),
        )
        return tokens
    }

    companion object {
        private val log = LoggerFactory.getLogger(RefreshTokenService::class.java)
    }
}
