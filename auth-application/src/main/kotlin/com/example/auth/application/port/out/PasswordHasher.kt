package com.example.auth.application.port.out

/**
 * 비밀번호 해시 / 검증 port. 구현체는 BCrypt cost=12 를 강제 (adapter-out).
 *
 * application 계층은 알고리즘에 무관 — interface 만 다룬다. 단, cost 정책은 도메인의
 * 보안 결정이므로 구현체 교체 시 ADR 갱신이 필요합니다.
 */
interface PasswordHasher {

    fun hash(rawPassword: String): String

    fun matches(rawPassword: String, hash: String): Boolean
}
