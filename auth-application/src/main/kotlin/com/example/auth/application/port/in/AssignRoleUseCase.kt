package com.example.auth.application.port.`in`

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import java.util.UUID

interface AssignRoleUseCase {

    fun assign(cmd: Command)

    @JvmRecord
    data class Command(
        val tenantId: TenantId,
        val targetUserId: UserId,
        val roleId: UUID,
        val actorUserId: UserId,
        val ipAddress: String?,
    )
}
