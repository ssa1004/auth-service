package com.example.auth.application.service

import com.example.auth.application.port.`in`.ListMySessionsUseCase
import com.example.auth.application.port.`in`.ListMySessionsUseCase.SessionView
import com.example.auth.application.port.out.RefreshTokenRepository
import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class ListMySessionsService(
    private val refreshTokenRepository: RefreshTokenRepository,
) : ListMySessionsUseCase {

    @Transactional(readOnly = true)
    override fun list(tenantId: TenantId, userId: UserId): List<SessionView> =
        refreshTokenRepository.findActiveByUser(tenantId, userId).map { t ->
            SessionView(
                t.id,
                t.deviceLabel,
                t.ipAddress,
                t.issuedAt,
                t.lastUsedAt,
                t.expiresAt,
            )
        }
}
