package com.example.auth.application.service;

import com.example.auth.application.port.in.ListMySessionsUseCase;
import com.example.auth.application.port.out.RefreshTokenRepository;
import com.example.auth.domain.common.TenantId;
import com.example.auth.domain.common.UserId;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class ListMySessionsService implements ListMySessionsUseCase {

    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    @Transactional(readOnly = true)
    public List<SessionView> list(TenantId tenantId, UserId userId) {
        return refreshTokenRepository.findActiveByUser(tenantId, userId).stream()
                .map(t -> new SessionView(
                        t.id(),
                        t.deviceLabel(),
                        t.ipAddress(),
                        t.issuedAt(),
                        t.lastUsedAt(),
                        t.expiresAt()))
                .toList();
    }
}
