package com.example.auth.application.service;

import com.example.auth.application.exception.InvalidCredentialsException;
import com.example.auth.application.port.in.AuditLoginAttemptsUseCase;
import com.example.auth.application.port.in.RevokeSessionUseCase;
import com.example.auth.application.port.out.RefreshTokenRepository;
import com.example.auth.domain.audit.AuditEventType;
import com.example.auth.domain.token.RefreshToken;
import java.time.Clock;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RevokeSessionService implements RevokeSessionUseCase {

    private final RefreshTokenRepository refreshTokenRepository;
    private final AuditLoginAttemptsUseCase auditUseCase;
    private final Clock clock;

    @Override
    @Transactional
    public void revoke(Command cmd) {
        // 사용자가 가진 *활성* 세션 중 sessionId 매칭. 다른 사용자 세션 revoke 시도는
        // findActiveByUser 가 안 보여주므로 자동으로 InvalidCredentialsException 으로 떨어짐.
        RefreshToken target = refreshTokenRepository.findActiveByUser(cmd.tenantId(), cmd.userId())
                .stream()
                .filter(t -> t.id().equals(cmd.sessionId()))
                .findFirst()
                .orElseThrow(InvalidCredentialsException::new);

        refreshTokenRepository.save(target.markRevokedByUser(clock.instant()));
        auditUseCase.record(
                cmd.tenantId(), cmd.userId(), AuditEventType.SESSION_REVOKED_BY_USER,
                cmd.ipAddress(), null,
                Map.of("sessionId", cmd.sessionId().toString()));
    }
}
