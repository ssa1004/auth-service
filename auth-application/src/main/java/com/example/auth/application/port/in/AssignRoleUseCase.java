package com.example.auth.application.port.in;

import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import java.util.UUID;

public interface AssignRoleUseCase {

    void assign(Command cmd);

    record Command(
            TenantId tenantId,
            UserId targetUserId,
            UUID roleId,
            UserId actorUserId,
            String ipAddress) {
    }
}
