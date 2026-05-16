package com.example.auth.application.port.out

import com.example.auth.application.security.AccessTokenClaims

/**
 * Access JWT 발급 port. 구현체는 Spring Authorization Server / Nimbus JOSE 기반
 * (adapter-out / bootstrap).
 *
 * 이 port 는 서명 키 / 알고리즘 / kid header 를 직접 다루지 않습니다 — 구현체가 현재
 * 회전 중인 JWK 를 사용합니다.
 */
interface AccessTokenIssuer {

    fun issue(claims: AccessTokenClaims): String
}
