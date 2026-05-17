package com.example.auth.adapter.`in`.security

import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.stereotype.Component

/**
 * JWT 의 `roles` + `permissions` claim 을 Spring Security 의 GrantedAuthority 로 변환.
 * 이렇게 매핑해 두면 `@PreAuthorize("hasAuthority('PERMISSION_billing:read')")` 같은 표현식이 동작합니다.
 */
@Component
class JwtPermissionsConverter : Converter<Jwt, AbstractAuthenticationToken> {

    override fun convert(jwt: Jwt): AbstractAuthenticationToken {
        val authorities: MutableCollection<GrantedAuthority> = ArrayList()
        val roles: List<String>? = jwt.getClaimAsStringList("roles")
        if (roles != null) {
            for (role in roles) authorities.add(SimpleGrantedAuthority("ROLE_$role"))
        }
        val perms: List<String>? = jwt.getClaimAsStringList("permissions")
        if (perms != null) {
            for (p in perms) authorities.add(SimpleGrantedAuthority("PERMISSION_$p"))
        }
        return JwtAuthenticationToken(jwt, authorities, jwt.subject)
    }
}
