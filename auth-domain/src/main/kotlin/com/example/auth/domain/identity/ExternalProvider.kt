package com.example.auth.domain.identity

/**
 * OIDC IdP vendor (ADR-0013). 본 단계는 GOOGLE 만 wiring 하지만 enum 으로 두어 추가
 * vendor (Microsoft, GitHub) 가 같은 도메인 흐름을 재사용하도록 한다.
 */
enum class ExternalProvider {
    GOOGLE,
    MICROSOFT,
    GITHUB,
}
