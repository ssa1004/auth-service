package com.example.auth.adapter.out.persistence.role;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "user_roles")
public class UserRoleEntity {

    @EmbeddedId
    private Pk id;

    protected UserRoleEntity() {}

    public UserRoleEntity(UUID userId, UUID roleId) {
        this.id = new Pk(userId, roleId);
    }

    public Pk getId() { return id; }

    @Embeddable
    public static class Pk implements Serializable {
        @Column(name = "user_id", nullable = false)
        private UUID userId;

        @Column(name = "role_id", nullable = false)
        private UUID roleId;

        protected Pk() {}

        public Pk(UUID userId, UUID roleId) {
            this.userId = userId;
            this.roleId = roleId;
        }

        public UUID getUserId() { return userId; }
        public UUID getRoleId() { return roleId; }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Pk pk)) return false;
            return Objects.equals(userId, pk.userId) && Objects.equals(roleId, pk.roleId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(userId, roleId);
        }
    }
}
