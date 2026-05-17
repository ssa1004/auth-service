package com.example.auth.adapter.out.security

import com.example.auth.application.port.out.PasswordHasher
import com.example.auth.application.security.AuthProperties
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Component

/**
 * BCrypt 구현체. cost 는 [AuthProperties.bcryptCost] (기본 12).
 *
 * cost=12 는 2026년 기준 ~250ms (M1) — 사용자 체감 한계 + brute force 방어 사이의 정책
 * 결정. ADR-0001 / ADR-0007 참고.
 */
@Component
class BCryptPasswordHasherAdapter(properties: AuthProperties) : PasswordHasher {

    private val encoder: BCryptPasswordEncoder = BCryptPasswordEncoder(properties.bcryptCost)

    override fun hash(rawPassword: String): String = encoder.encode(rawPassword)

    override fun matches(rawPassword: String, hash: String): Boolean =
        encoder.matches(rawPassword, hash)
}
