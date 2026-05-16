package com.example.auth.application.port.out

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import java.time.Duration
import java.util.Optional

/**
 * MFA 1단계 (비밀번호 통과) → 2단계 (TOTP 코드 입력) 사이의 짧은 challenge 보관소.
 *
 * 구현체는 Redis (TTL 5분 권장). 토큰은 CSPRNG 생성, 검증 후 즉시 삭제 (replay 차단).
 *
 * tenantId 도 같이 보관 — challenge 발급 시점의 테넌트 컨텍스트가 그대로 살아있어야
 * cross-tenant 공격을 차단할 수 있습니다.
 */
interface MfaChallengeStore {

    fun issueChallenge(tenantId: TenantId, userId: UserId, ttl: Duration): String

    fun consume(challengeToken: String): Optional<Challenge>

    @JvmRecord
    data class Challenge(val tenantId: TenantId, val userId: UserId)
}
