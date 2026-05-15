package com.example.auth.domain.common

import java.util.UUID

/**
 * 사용자 식별자. JWT subject (`sub`) 로도 사용됩니다.
 *
 * `value` 는 non-null — Kotlin 컴파일러가 Java 호출자용 null 가드를 자동 생성한다.
 */
@JvmRecord
data class UserId(val value: UUID) {

    fun asString(): String = value.toString()

    companion object {
        @JvmStatic
        fun of(value: UUID): UserId = UserId(value)

        @JvmStatic
        fun of(value: String): UserId = UserId(UUID.fromString(value))

        @JvmStatic
        fun newId(): UserId = UserId(UUID.randomUUID())
    }
}
