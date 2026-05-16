package com.example.auth.application.service

import com.example.auth.application.exception.InvalidCredentialsException
import com.example.auth.application.exception.RateLimitedException
import com.example.auth.application.port.`in`.AuditLoginAttemptsUseCase
import com.example.auth.application.port.`in`.VerifyMfaUseCase
import com.example.auth.application.port.out.MfaChallengeStore
import com.example.auth.application.port.out.MfaSecretCipher
import com.example.auth.application.port.out.MfaSecretRepository
import com.example.auth.application.port.out.RateLimiter
import com.example.auth.application.port.out.TenantRepository
import com.example.auth.application.port.out.TotpVerifier
import com.example.auth.application.port.out.UserRepository
import com.example.auth.application.security.AuthTokens
import com.example.auth.domain.audit.AuditEventType
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class VerifyMfaService(
    private val mfaChallengeStore: MfaChallengeStore,
    private val userRepository: UserRepository,
    private val tenantRepository: TenantRepository,
    private val mfaSecretRepository: MfaSecretRepository,
    private val mfaSecretCipher: MfaSecretCipher,
    private val totpVerifier: TotpVerifier,
    private val rateLimiter: RateLimiter,
    private val sessionIssuer: SessionIssuer,
    private val auditUseCase: AuditLoginAttemptsUseCase,
) : VerifyMfaUseCase {

    @Transactional
    override fun verify(cmd: VerifyMfaUseCase.Command): AuthTokens {
        // OWASP API4 — verify-mfa 도 인증 없이 호출되는 endpoint. 6자리 TOTP 는 공간이
        // 좁아 (10^6) re-login → mfaToken 재발급 → 추측 루프로 brute-force 가 가능합니다.
        // login / register / refresh 와 같은 IP 별 token bucket 으로 추측 속도를 직접 제한
        // — login bucket 에 간접적으로 기대지 않고 endpoint 자체에 가드를 둡니다. ip 가 null
        // 인 단위 테스트 경로는 우회 (e2e / 운영은 ClientIpResolver 가 항상 채움).
        if (cmd.ipAddress != null) {
            val rateKey = "verify-mfa:${cmd.ipAddress}"
            if (!rateLimiter.tryConsume(rateKey)) {
                throw RateLimitedException()
            }
        }
        val challenge = mfaChallengeStore.consume(cmd.mfaChallengeToken)
            .orElseThrow { InvalidCredentialsException() }
        val userId = challenge.userId
        val tenant = tenantRepository.findById(challenge.tenantId)
            .orElseThrow { InvalidCredentialsException() }
        val user = userRepository.findById(tenant.id, userId)
            .orElseThrow { InvalidCredentialsException() }

        val secret = mfaSecretRepository.findByUser(userId)
            .orElseThrow { InvalidCredentialsException() }
        // 평문 secret 은 검증 직전에만 잠시 풀고, verify 호출 후 변수 범위를 벗어나면 GC 대상.
        val plaintext = mfaSecretCipher.decrypt(secret.secretCipher)
        val ok = totpVerifier.verify(plaintext, cmd.code)
        if (!ok) {
            auditUseCase.record(
                tenant.id, userId, AuditEventType.MFA_FAILED,
                cmd.ipAddress, cmd.userAgent, emptyMap(),
            )
            throw InvalidCredentialsException()
        }

        val tokens = sessionIssuer.issue(
            tenant, user, setOf("pwd", "mfa"), cmd.ipAddress, cmd.userAgent, cmd.deviceLabel,
        )
        auditUseCase.record(
            tenant.id, userId, AuditEventType.MFA_VERIFIED,
            cmd.ipAddress, cmd.userAgent, emptyMap(),
        )
        return tokens
    }
}
