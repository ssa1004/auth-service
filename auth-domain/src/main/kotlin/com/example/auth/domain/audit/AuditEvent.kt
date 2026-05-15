package com.example.auth.domain.audit

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import java.time.Instant
import java.util.Collections
import java.util.TreeMap
import java.util.UUID

/**
 * Append-only audit 이벤트. 한 번 적재되면 절대 수정되지 않습니다 (ADR-0008).
 *
 * `payload` 는 자유 형식 JSON-able map. 단, 평문 비밀번호 / TOTP secret /
 * refresh token 평문은 절대 들어가서는 안 됩니다 — application 에서 호출 전에 마스킹된
 * 형태로만 넘겨야 합니다.
 *
 * `@JvmRecord data class` — Java 호출자 (`e.id()` / `e.tenantId()` / `e.payload()`
 * record-style accessor) 그대로 동작. `userId` 는 미인증 실패 시점 (로그인 실패 —
 * username 못 찾음) 에 null 가능.
 */
@JvmRecord
data class AuditEvent(
    val id: UUID,
    val tenantId: TenantId,
    val userId: UserId?,
    val type: AuditEventType,
    val ipAddress: String?,
    val userAgent: String?,
    val payload: Map<String, String>,
    val occurredAt: Instant,
) {

    companion object {
        @JvmStatic
        fun of(
            tenantId: TenantId,
            userId: UserId?,
            type: AuditEventType,
            ipAddress: String?,
            userAgent: String?,
            payload: Map<String, String>?,
            now: Instant,
        ): AuditEvent = AuditEvent(
            UUID.randomUUID(),
            tenantId,
            userId,
            type,
            ipAddress,
            userAgent,
            // Java compact constructor 의 정규화 (정렬 + 불변 복사) 를 factory 에서 수행.
            normalizePayload(payload),
            now,
        )

        /** null → 빈 map, 그 외엔 key 정렬된 불변 복사본. */
        @JvmStatic
        private fun normalizePayload(payload: Map<String, String>?): Map<String, String> =
            if (payload == null) emptyMap() else Collections.unmodifiableMap(TreeMap(payload))
    }
}
