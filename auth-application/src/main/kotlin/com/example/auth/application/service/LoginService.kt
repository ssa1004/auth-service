package com.example.auth.application.service

import com.example.auth.application.exception.InvalidCredentialsException
import com.example.auth.application.exception.MfaRequiredException
import com.example.auth.application.exception.RateLimitedException
import com.example.auth.application.exception.TenantNotFoundException
import com.example.auth.application.port.`in`.AuditLoginAttemptsUseCase
import com.example.auth.application.port.`in`.LoginUseCase
import com.example.auth.application.port.out.MfaChallengeStore
import com.example.auth.application.port.out.PasswordHasher
import com.example.auth.application.port.out.RateLimiter
import com.example.auth.application.port.out.TenantRepository
import com.example.auth.application.port.out.UserRepository
import com.example.auth.application.security.AuthProperties
import com.example.auth.application.security.AuthTokens
import com.example.auth.domain.audit.AuditEventType
import com.example.auth.domain.common.EmailMasker
import java.time.Duration
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class LoginService(
    private val userRepository: UserRepository,
    private val tenantRepository: TenantRepository,
    private val passwordHasher: PasswordHasher,
    private val rateLimiter: RateLimiter,
    private val mfaChallengeStore: MfaChallengeStore,
    private val sessionIssuer: SessionIssuer,
    private val auditUseCase: AuditLoginAttemptsUseCase,
    private val properties: AuthProperties,
) : LoginUseCase {

    @Transactional
    override fun login(cmd: LoginUseCase.Command): AuthTokens {
        val tenant = tenantRepository.findBySlug(cmd.tenantSlug)
            .orElseThrow { TenantNotFoundException(cmd.tenantSlug) }
        val email = cmd.email.lowercase().trim()
        val rateKey = "login:${tenant.slug}:${cmd.ipAddress}:$email"
        if (!rateLimiter.tryConsume(rateKey)) {
            auditUseCase.record(
                tenant.id, null, AuditEventType.LOGIN_FAILED_RATE_LIMITED,
                cmd.ipAddress, cmd.userAgent,
                mapOf("email" to EmailMasker.mask(email)),
            )
            throw RateLimitedException()
        }

        val userOpt = userRepository.findByEmail(tenant.id, email)
        if (userOpt.isEmpty) {
            // 사용자 미존재여도 *bad credentials* 와 동일한 응답 (정보 누설 방지).
            auditUseCase.record(
                tenant.id, null, AuditEventType.LOGIN_FAILED_BAD_CREDENTIALS,
                cmd.ipAddress, cmd.userAgent,
                mapOf("email" to EmailMasker.mask(email), "reason" to "user_not_found"),
            )
            throw InvalidCredentialsException()
        }
        val user = userOpt.get()
        if (!user.canLogin()) {
            auditUseCase.record(
                tenant.id, user.id, AuditEventType.LOGIN_FAILED_USER_LOCKED,
                cmd.ipAddress, cmd.userAgent,
                mapOf("email" to EmailMasker.mask(email), "status" to user.status.name),
            )
            throw InvalidCredentialsException()
        }
        if (!passwordHasher.matches(cmd.rawPassword, user.passwordHash)) {
            auditUseCase.record(
                tenant.id, user.id, AuditEventType.LOGIN_FAILED_BAD_CREDENTIALS,
                cmd.ipAddress, cmd.userAgent,
                mapOf("email" to EmailMasker.mask(email), "reason" to "password_mismatch"),
            )
            throw InvalidCredentialsException()
        }

        if (user.requiresMfa()) {
            val challenge = mfaChallengeStore.issueChallenge(tenant.id, user.id, Duration.ofMinutes(5))
            auditUseCase.record(
                tenant.id, user.id, AuditEventType.MFA_REQUIRED,
                cmd.ipAddress, cmd.userAgent,
                mapOf("email" to EmailMasker.mask(email)),
            )
            throw MfaRequiredException(challenge)
        }

        val tokens = sessionIssuer.issue(
            tenant, user, setOf("pwd"), cmd.ipAddress, cmd.userAgent, cmd.deviceLabel,
        )
        auditUseCase.record(
            tenant.id, user.id, AuditEventType.LOGIN_SUCCEEDED,
            cmd.ipAddress, cmd.userAgent,
            mapOf("email" to EmailMasker.mask(email)),
        )
        return tokens
    }
}
