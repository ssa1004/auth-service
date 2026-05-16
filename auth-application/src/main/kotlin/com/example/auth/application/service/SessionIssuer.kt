package com.example.auth.application.service

import com.example.auth.application.port.out.AccessTokenIssuer
import com.example.auth.application.port.out.RefreshTokenGenerator
import com.example.auth.application.port.out.RefreshTokenRepository
import com.example.auth.application.port.out.RoleRepository
import com.example.auth.application.security.AccessTokenClaims
import com.example.auth.application.security.AuthProperties
import com.example.auth.application.security.AuthTokens
import com.example.auth.domain.role.Permission
import com.example.auth.domain.tenant.Tenant
import com.example.auth.domain.token.RefreshToken
import com.example.auth.domain.token.TokenHasher
import com.example.auth.domain.user.User
import java.time.Clock
import java.util.LinkedHashSet
import java.util.UUID
import org.springframework.stereotype.Component

/**
 * 로그인 / MFA / refresh 가 공통으로 호출하는 access + refresh 발급 핸드.
 *
 * refresh token 평문은 [AuthTokens] 안에서 한 번 노출되고, 이후 메모리 / DB /
 * 로그 어디에도 평문이 머물지 않습니다 — DB 에는 SHA-256 hash 만.
 */
@Component
class SessionIssuer(
    private val accessTokenIssuer: AccessTokenIssuer,
    private val refreshTokenGenerator: RefreshTokenGenerator,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val roleRepository: RoleRepository,
    private val properties: AuthProperties,
    private val clock: Clock,
) {

    fun issue(
        tenant: Tenant,
        user: User,
        amr: Set<String>,
        ipAddress: String?,
        userAgent: String?,
        deviceLabel: String?,
    ): AuthTokens = issue(tenant, user, amr, ipAddress, userAgent, deviceLabel, null)

    fun issue(
        tenant: Tenant,
        user: User,
        amr: Set<String>,
        ipAddress: String?,
        userAgent: String?,
        deviceLabel: String?,
        parentRefreshId: UUID?,
    ): AuthTokens {
        val roles = roleRepository.findByUser(tenant.id, user.id)

        val roleSlugs = LinkedHashSet<String>()
        val perms = LinkedHashSet<Permission>()
        for (r in roles) {
            roleSlugs.add(r.slug)
            perms.addAll(r.permissions)
        }

        val claims = AccessTokenClaims.forUser(
            user.id, tenant.id, roleSlugs, perms, amr, properties.accessTokenTtl,
        )
        val accessToken = accessTokenIssuer.issue(claims)

        val refreshPlain = refreshTokenGenerator.generate()
        val refreshHash = TokenHasher.sha256(refreshPlain)
        val now = clock.instant()
        val refresh = RefreshToken.issue(
            tenant.id, user.id, refreshHash, parentRefreshId,
            deviceLabel, ipAddress, now, now.plus(properties.refreshTokenTtl),
        )
        refreshTokenRepository.save(refresh)

        return AuthTokens.bearer(
            accessToken,
            refreshPlain,
            properties.accessTokenTtl,
            properties.refreshTokenTtl,
        )
    }
}
