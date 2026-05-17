package com.example.auth.adapter.out.persistence.role

import jakarta.persistence.Column
import jakarta.persistence.Embeddable
import jakarta.persistence.EmbeddedId
import jakarta.persistence.Entity
import jakarta.persistence.Table
import java.io.Serializable
import java.util.UUID

@Entity
@Table(name = "user_roles")
class UserRoleEntity {

    @EmbeddedId
    private var id: Pk = Pk()

    constructor()

    constructor(userId: UUID, roleId: UUID) {
        this.id = Pk(userId, roleId)
    }

    fun getId(): Pk = id

    @Embeddable
    class Pk : Serializable {

        @Column(name = "user_id", nullable = false)
        private var userId: UUID = UUID(0, 0)

        @Column(name = "role_id", nullable = false)
        private var roleId: UUID = UUID(0, 0)

        constructor()

        constructor(userId: UUID, roleId: UUID) {
            this.userId = userId
            this.roleId = roleId
        }

        fun getUserId(): UUID = userId
        fun getRoleId(): UUID = roleId

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Pk) return false
            return userId == other.userId && roleId == other.roleId
        }

        override fun hashCode(): Int {
            var result = userId.hashCode()
            result = 31 * result + roleId.hashCode()
            return result
        }
    }
}
