package com.example.auth.adapter.out.persistence.identity;

import com.example.auth.domain.common.UserId;
import com.example.auth.domain.identity.ExternalIdentity;
import com.example.auth.domain.identity.ExternalProvider;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "external_identities", uniqueConstraints = @UniqueConstraint(
        name = "external_identities_provider_subject_uq",
        columnNames = {"provider", "provider_user_id"}))
public class ExternalIdentityEntity {

    @Id
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(nullable = false)
    private String provider;

    @Column(name = "provider_user_id", nullable = false)
    private String providerUserId;

    @Column(name = "email_at_link")
    private String emailAtLink;

    @Column(name = "linked_at", nullable = false)
    private Instant linkedAt;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    protected ExternalIdentityEntity() {}

    public static ExternalIdentityEntity from(ExternalIdentity i) {
        ExternalIdentityEntity e = new ExternalIdentityEntity();
        e.id = i.id();
        e.userId = i.userId().value();
        e.provider = i.provider().name();
        e.providerUserId = i.providerUserId();
        e.emailAtLink = i.emailAtLink();
        e.linkedAt = i.linkedAt();
        e.lastLoginAt = i.lastLoginAt();
        return e;
    }

    public ExternalIdentity toDomain() {
        return new ExternalIdentity(
                id, UserId.of(userId), ExternalProvider.valueOf(provider),
                providerUserId, emailAtLink, linkedAt, lastLoginAt);
    }
}
