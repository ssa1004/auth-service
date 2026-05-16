package com.example.auth.application.service

import com.example.auth.application.exception.RateLimitedException
import com.example.auth.application.exception.TenantNotFoundException
import com.example.auth.application.exception.UserAlreadyExistsException
import com.example.auth.application.port.`in`.AuditLoginAttemptsUseCase
import com.example.auth.application.port.`in`.RegisterUserUseCase
import com.example.auth.application.port.out.PasswordHasher
import com.example.auth.application.port.out.RateLimiter
import com.example.auth.application.port.out.TenantRepository
import com.example.auth.application.port.out.UserRepository
import com.example.auth.application.port.out.VerificationMailSender
import com.example.auth.domain.audit.AuditEventType
import com.example.auth.domain.common.EmailMasker
import com.example.auth.domain.common.UserId
import com.example.auth.domain.user.User
import java.time.Clock
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class RegisterUserService(
    private val userRepository: UserRepository,
    private val tenantRepository: TenantRepository,
    private val passwordHasher: PasswordHasher,
    private val mailSender: VerificationMailSender,
    private val rateLimiter: RateLimiter,
    private val auditUseCase: AuditLoginAttemptsUseCase,
    private val clock: Clock,
) : RegisterUserUseCase {

    @Transactional
    override fun register(cmd: RegisterUserUseCase.Command): UserId {
        val tenant = tenantRepository.findBySlug(cmd.tenantSlug)
            .orElseThrow { TenantNotFoundException(cmd.tenantSlug) }
        if (!tenant.isActive()) {
            throw TenantNotFoundException(cmd.tenantSlug)
        }
        // OWASP API4 / API6 — register 는 인증 없이 호출되므로 IP 별 token bucket 으로
        // 자동 가입 / 계정 enumeration (409 응답을 oracle 로 활용) 을 차단합니다. login 과
        // 같은 bucket 설정 (10 req/min) 을 별도 키로 사용 — 사용자 합법 가입 흐름은 영향 X.
        if (cmd.ipAddress != null) {
            val rateKey = "register:${tenant.slug}:${cmd.ipAddress}"
            if (!rateLimiter.tryConsume(rateKey)) {
                throw RateLimitedException()
            }
        }
        val email = cmd.email.lowercase().trim()
        if (userRepository.existsByEmail(tenant.id, email)) {
            throw UserAlreadyExistsException()
        }
        val hash = passwordHasher.hash(cmd.rawPassword)
        val user = User.register(tenant.id, email, hash, clock.instant())
        val saved = userRepository.save(user)

        // 메일 발송 — 운영에서는 verification token + signed link 가 들어가지만 본 단계에서는
        // mock 으로 충분. 평문 비밀번호는 메일에도 절대 들어가면 안 됩니다.
        mailSender.sendVerification(email, "https://auth.example.com/verify?token=...")

        auditUseCase.record(
            tenant.id,
            saved.id,
            AuditEventType.USER_REGISTERED,
            null,
            null,
            mapOf("email" to EmailMasker.mask(email)),
        )

        log.info(
            "user registered tenant={} user={} email={}",
            tenant.slug, saved.id.asString(), EmailMasker.mask(email),
        )
        return saved.id
    }

    companion object {
        private val log = LoggerFactory.getLogger(RegisterUserService::class.java)
    }
}
