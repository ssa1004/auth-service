package com.example.auth.adapter.out.persistence.role

import java.util.UUID
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param

interface UserRoleJpaRepository : JpaRepository<UserRoleEntity, UserRoleEntity.Pk> {

    @Query("select ur.id.roleId from UserRoleEntity ur where ur.id.userId = :userId")
    fun findRoleIdsByUserId(@Param("userId") userId: UUID): List<UUID>

    fun deleteById_UserIdAndId_RoleId(userId: UUID, roleId: UUID)
}
