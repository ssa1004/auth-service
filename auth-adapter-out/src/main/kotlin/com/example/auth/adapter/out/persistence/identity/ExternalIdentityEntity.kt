package com.example.auth.adapter.out.persistence.identity

import com.example.auth.domain.common.UserId
import com.example.auth.domain.identity.ExternalIdentity
import com.example.auth.domain.identity.ExternalProvider
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import jakarta.persistence.UniqueConstraint
import java.time.Instant
import java.util.UUID

@Entity
@Table(
    name = "external_identities",
    uniqueConstraints = [
        UniqueConstraint(
            name = "external_identities_provider_subject_uq",
            columnNames = ["provider", "provider_user_id"],
        ),
    ],
)
class ExternalIdentityEntity {

    @Id
    private var id: UUID = UUID(0, 0)

    @Column(name = "user_id", nullable = false)
    private var userId: UUID = UUID(0, 0)

    @Column(nullable = false)
    private var provider: String = ""

    @Column(name = "provider_user_id", nullable = false)
    private var providerUserId: String = ""

    @Column(name = "email_at_link")
    private var emailAtLink: String? = null

    @Column(name = "linked_at", nullable = false)
    private var linkedAt: Instant = Instant.EPOCH

    @Column(name = "last_login_at")
    private var lastLoginAt: Instant? = null

    fun toDomain(): ExternalIdentity = ExternalIdentity(
        id, UserId.of(userId), ExternalProvider.valueOf(provider),
        providerUserId, emailAtLink, linkedAt, lastLoginAt,
    )

    companion object {
        @JvmStatic
        fun from(i: ExternalIdentity): ExternalIdentityEntity = ExternalIdentityEntity().apply {
            id = i.id
            userId = i.userId.value
            provider = i.provider.name
            providerUserId = i.providerUserId
            emailAtLink = i.emailAtLink
            linkedAt = i.linkedAt
            lastLoginAt = i.lastLoginAt
        }
    }
}
