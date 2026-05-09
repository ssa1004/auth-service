package com.example.auth.application.port.in;

import com.example.auth.domain.identity.ExternalProvider;
import com.example.auth.domain.user.User;

/**
 * OIDC IdP 의 callback 을 받아 사용자 도메인 {@link User} 와 매핑하는 use case (ADR-0013).
 *
 * <p>흐름 — 기존 매핑 → 같은 이메일 사용자 link → 자동 가입.
 */
public interface LinkOrCreateUserFromOidcUseCase {

    User linkOrCreate(Command cmd);

    record Command(
            String tenantSlug,
            ExternalProvider provider,
            String providerUserId,
            String email) {
    }
}
