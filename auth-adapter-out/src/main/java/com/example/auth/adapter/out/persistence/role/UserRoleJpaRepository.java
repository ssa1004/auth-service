package com.example.auth.adapter.out.persistence.role;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRoleJpaRepository
        extends JpaRepository<UserRoleEntity, UserRoleEntity.Pk> {

    @Query("select ur.id.roleId from UserRoleEntity ur where ur.id.userId = :userId")
    List<UUID> findRoleIdsByUserId(@Param("userId") UUID userId);

    void deleteById_UserIdAndId_RoleId(UUID userId, UUID roleId);
}
