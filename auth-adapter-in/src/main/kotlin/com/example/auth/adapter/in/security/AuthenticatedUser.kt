package com.example.auth.adapter.`in`.security

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId

/**
 * 컨트롤러 method argument 로 주입되는 인증된 사용자 컨텍스트. JWT 의 `sub` +
 * `tnt` claim 에서 풀어 만들어집니다 ([AuthenticatedUserResolver]).
 */
@JvmRecord
data class AuthenticatedUser(val userId: UserId, val tenantId: TenantId)
