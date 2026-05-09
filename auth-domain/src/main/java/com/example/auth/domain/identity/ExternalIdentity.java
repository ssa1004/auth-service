package com.example.auth.domain.identity;

import com.example.auth.domain.common.UserId;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * 외부 IdP (Google / Microsoft / GitHub OIDC) 로 로그인한 사용자의 매핑 (ADR-0013).
 *
 * <p>같은 사용자가 여러 vendor 로 로그인할 수 있으므로 하나의 {@link UserId} 에 여러 row 가
 * 매달릴 수 있습니다. 단 {@code (provider, providerUserId)} 는 globally unique — 같은
 * Google 계정이 두 사용자에 매달리는 케이스 차단.
 */
public final class ExternalIdentity {

    private final UUID id;
    private final UserId userId;
    private final ExternalProvider provider;
    /** IdP 측 user 의 sub. Google: numeric ID. Microsoft: oid. */
    private final String providerUserId;
    /** 가입 시점 IdP 가 알려준 이메일 — 추적용. 매핑 자체는 providerUserId 가 진실. */
    private final String emailAtLink;
    private final Instant linkedAt;
    private final Instant lastLoginAt;

    public ExternalIdentity(UUID id,
                            UserId userId,
                            ExternalProvider provider,
                            String providerUserId,
                            String emailAtLink,
                            Instant linkedAt,
                            Instant lastLoginAt) {
        this.id = Objects.requireNonNull(id);
        this.userId = Objects.requireNonNull(userId);
        this.provider = Objects.requireNonNull(provider);
        this.providerUserId = Objects.requireNonNull(providerUserId);
        if (providerUserId.isBlank()) {
            throw new IllegalArgumentException("providerUserId 는 비어있을 수 없습니다");
        }
        this.emailAtLink = emailAtLink;
        this.linkedAt = Objects.requireNonNull(linkedAt);
        this.lastLoginAt = lastLoginAt;
    }

    public static ExternalIdentity link(UserId userId,
                                        ExternalProvider provider,
                                        String providerUserId,
                                        String emailAtLink,
                                        Instant now) {
        return new ExternalIdentity(
                UUID.randomUUID(), userId, provider, providerUserId, emailAtLink, now, now);
    }

    public ExternalIdentity touchLogin(Instant now) {
        return new ExternalIdentity(
                id, userId, provider, providerUserId, emailAtLink, linkedAt, now);
    }

    public UUID id() { return id; }
    public UserId userId() { return userId; }
    public ExternalProvider provider() { return provider; }
    public String providerUserId() { return providerUserId; }
    public String emailAtLink() { return emailAtLink; }
    public Instant linkedAt() { return linkedAt; }
    public Instant lastLoginAt() { return lastLoginAt; }
}
