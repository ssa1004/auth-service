package com.example.auth.application.service;

import com.example.auth.application.port.out.AccessTokenIssuer;
import com.example.auth.application.port.out.RefreshTokenGenerator;
import com.example.auth.application.port.out.RefreshTokenRepository;
import com.example.auth.application.port.out.RoleRepository;
import com.example.auth.application.security.AccessTokenClaims;
import com.example.auth.application.security.AuthProperties;
import com.example.auth.application.security.AuthTokens;
import com.example.auth.domain.role.Permission;
import com.example.auth.domain.role.Role;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.token.RefreshToken;
import com.example.auth.domain.token.TokenHasher;
import com.example.auth.domain.user.User;
import java.time.Clock;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * 로그인 / MFA / refresh 가 공통으로 호출하는 access + refresh 발급 핸드.
 *
 * <p>refresh token 평문은 {@link AuthTokens} 안에서 한 번 노출되고, 이후 메모리 / DB /
 * 로그 어디에도 평문이 머물지 않습니다 — DB 에는 SHA-256 hash 만.
 */
@Component
@RequiredArgsConstructor
public class SessionIssuer {

    private final AccessTokenIssuer accessTokenIssuer;
    private final RefreshTokenGenerator refreshTokenGenerator;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RoleRepository roleRepository;
    private final AuthProperties properties;
    private final Clock clock;

    public AuthTokens issue(
            Tenant tenant,
            User user,
            Set<String> amr,
            String ipAddress,
            String userAgent,
            String deviceLabel) {
        return issue(tenant, user, amr, ipAddress, userAgent, deviceLabel, null);
    }

    public AuthTokens issue(
            Tenant tenant,
            User user,
            Set<String> amr,
            String ipAddress,
            String userAgent,
            String deviceLabel,
            UUID parentRefreshId) {
        List<Role> roles = roleRepository.findByUser(tenant.id(), user.id());

        Set<String> roleSlugs = new LinkedHashSet<>();
        Set<Permission> perms = new LinkedHashSet<>();
        for (Role r : roles) {
            roleSlugs.add(r.slug());
            perms.addAll(r.permissions());
        }

        AccessTokenClaims claims = AccessTokenClaims.forUser(
                user.id(), tenant.id(), roleSlugs, perms, amr, properties.accessTokenTtl());
        String accessToken = accessTokenIssuer.issue(claims);

        String refreshPlain = refreshTokenGenerator.generate();
        String refreshHash = TokenHasher.sha256(refreshPlain);
        var now = clock.instant();
        RefreshToken refresh = RefreshToken.issue(
                tenant.id(), user.id(), refreshHash, parentRefreshId,
                deviceLabel, ipAddress, now, now.plus(properties.refreshTokenTtl()));
        refreshTokenRepository.save(refresh);

        return AuthTokens.bearer(
                accessToken,
                refreshPlain,
                properties.accessTokenTtl(),
                properties.refreshTokenTtl());
    }
}
