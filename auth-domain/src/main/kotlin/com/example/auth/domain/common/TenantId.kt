package com.example.auth.domain.common

import java.util.UUID

/**
 * 테넌트 식별자. JWT 의 `tnt` claim 에 담기며 모든 도메인 객체가 이 값을 통해
 * 격리됩니다. value object 로 강제하여 raw String/UUID 가 도메인 메서드 시그니처에 노출되지
 * 않도록 합니다.
 *
 * `value` 는 non-null — Kotlin 컴파일러가 Java 호출자용 null 가드를 자동 생성한다.
 */
@JvmRecord
data class TenantId(val value: UUID) {

    fun asString(): String = value.toString()

    companion object {
        @JvmStatic
        fun of(value: UUID): TenantId = TenantId(value)

        @JvmStatic
        fun of(value: String): TenantId = TenantId(UUID.fromString(value))

        @JvmStatic
        fun newId(): TenantId = TenantId(UUID.randomUUID())
    }
}
