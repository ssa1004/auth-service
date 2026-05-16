package com.example.auth.application.service

import com.example.auth.application.exception.TenantNotFoundException
import com.example.auth.application.port.`in`.AuditLoginAttemptsUseCase
import com.example.auth.application.port.`in`.LinkOrCreateUserFromOidcUseCase
import com.example.auth.application.port.out.ExternalIdentityRepository
import com.example.auth.application.port.out.PasswordHasher
import com.example.auth.application.port.out.TenantRepository
import com.example.auth.application.port.out.UserRepository
import com.example.auth.domain.audit.AuditEventType
import com.example.auth.domain.common.EmailMasker
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.identity.ExternalIdentity
import com.example.auth.domain.identity.ExternalProvider
import com.example.auth.domain.user.User
import java.security.SecureRandom
import java.time.Clock
import java.util.Base64
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

/**
 * OIDC callback 처리 (ADR-0013).
 *
 * 매핑 우선순위:
 * 1. `(provider, providerUserId)` 로 기존 외부 매핑 조회 → user 그대로 사용 (last_login_at 갱신).
 * 2. 같은 테넌트의 같은 이메일 사용자가 있으면 link — 외부 매핑만 추가하고 기존 user 사용.
 * 3. 아무 매핑 / 사용자 없음 → 자동 가입 — 비밀번호는 랜덤 (사용자가 OIDC 로만 로그인).
 *    이후 로컬 비밀번호 로그인을 원하면 비밀번호 재설정 흐름.
 */
@Service
class LinkOrCreateUserFromOidcService(
    private val externalIdentityRepository: ExternalIdentityRepository,
    private val userRepository: UserRepository,
    private val tenantRepository: TenantRepository,
    private val passwordHasher: PasswordHasher,
    private val auditUseCase: AuditLoginAttemptsUseCase,
    private val clock: Clock,
) : LinkOrCreateUserFromOidcUseCase {

    @Transactional
    override fun linkOrCreate(cmd: LinkOrCreateUserFromOidcUseCase.Command): User {
        val tenant = tenantRepository.findBySlug(cmd.tenantSlug)
            .orElseThrow { TenantNotFoundException(cmd.tenantSlug) }
        if (!tenant.isActive()) {
            throw TenantNotFoundException(cmd.tenantSlug)
        }
        val email: String? = cmd.email?.lowercase()?.trim()

        // 1. 외부 매핑 우선.
        val existing = externalIdentityRepository.findByProviderSubject(cmd.provider, cmd.providerUserId)
        if (existing.isPresent) {
            val touched = existing.get().touchLogin(clock.instant())
            externalIdentityRepository.save(touched)
            val user = userRepository.findById(tenant.id, touched.userId)
                .orElseThrow {
                    IllegalStateException(
                        "external_identities.user_id 가 사용자 도메인에 없음 — 데이터 무결성 사고",
                    )
                }
            audit(tenant.id, user, cmd.provider, email, "EXISTING_LINK")
            return user
        }

        // 2. 같은 테넌트의 같은 이메일 사용자에 link.
        if (email != null) {
            val byEmail = userRepository.findByEmail(tenant.id, email)
            if (byEmail.isPresent) {
                val user = byEmail.get()
                val link = ExternalIdentity.link(
                    user.id, cmd.provider, cmd.providerUserId, email, clock.instant(),
                )
                externalIdentityRepository.save(link)
                audit(tenant.id, user, cmd.provider, email, "LINKED_TO_EXISTING_USER")
                log.info(
                    "OIDC link 기존 사용자 tenant={} provider={} user={}",
                    tenant.slug, cmd.provider, user.id.asString(),
                )
                return user
            }
        }

        // 3. 자동 가입 — 비밀번호는 랜덤 32 byte (OIDC 외 로그인 차단). 사용자가 비밀번호 로그인을
        // 원하면 비밀번호 재설정 흐름으로 자신의 비밀번호를 새로 설정합니다.
        if (email == null || email.isBlank()) {
            throw IllegalArgumentException("OIDC 사용자 자동 가입에는 이메일이 필요합니다")
        }
        val randomSecret = base64Random(32)
        val passwordHash = passwordHasher.hash(randomSecret)
        val newUser = User.register(tenant.id, email, passwordHash, clock.instant())
            .markVerified(clock.instant())
        val saved = userRepository.save(newUser)

        val link = ExternalIdentity.link(
            saved.id, cmd.provider, cmd.providerUserId, email, clock.instant(),
        )
        externalIdentityRepository.save(link)

        audit(tenant.id, saved, cmd.provider, email, "AUTO_REGISTERED")
        log.info(
            "OIDC 자동 가입 tenant={} provider={} user={} email={}",
            tenant.slug, cmd.provider, saved.id.asString(), EmailMasker.mask(email),
        )
        return saved
    }

    private fun audit(
        tenantId: TenantId,
        user: User,
        provider: ExternalProvider,
        email: String?,
        result: String,
    ) {
        auditUseCase.record(
            tenantId,
            user.id,
            AuditEventType.USER_REGISTERED, // 본 단계는 별도 OIDC_LINKED 타입 추가 미보류
            null, // ip / userAgent 는 controller 단에서 채워서 보내는 것이 깔끔하지만 본 skeleton 은 단순화
            null,
            mapOf(
                "oidcProvider" to provider.name,
                "oidcResult" to result,
                "emailMasked" to if (email == null) "null" else EmailMasker.mask(email),
            ),
        )
    }

    companion object {
        private val SECURE_RANDOM = SecureRandom()

        private val log = LoggerFactory.getLogger(LinkOrCreateUserFromOidcService::class.java)

        private fun base64Random(byteLen: Int): String {
            val bytes = ByteArray(byteLen)
            SECURE_RANDOM.nextBytes(bytes)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        }
    }
}
