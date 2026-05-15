package com.example.auth.domain.role

/**
 * 가장 잘게 쪼갠 권한 단위. 형식은 `resource:action` (예: `billing:read`).
 *
 * RBAC 에서 grant 단위는 Role 이지만, JWT claim 에는 user 가 받은 모든 Role 의
 * permission 합집합을 담습니다. 이렇게 하면 검증 측 (consumer service) 은 role lookup
 * 없이 permission 만으로 인가 결정을 내릴 수 있습니다.
 *
 * `@JvmRecord data class` — Java 호출자 (`p.name()` record-style accessor) 그대로 동작.
 */
@JvmRecord
data class Permission(val name: String) {

    init {
        require(name.matches(FORMAT)) {
            "permission 형식은 'resource:action' 이어야 합니다: $name"
        }
    }

    companion object {
        private val FORMAT = Regex("[a-z][a-z0-9_]*:[a-z][a-z0-9_]*")

        @JvmStatic
        fun of(name: String): Permission = Permission(name)
    }
}
