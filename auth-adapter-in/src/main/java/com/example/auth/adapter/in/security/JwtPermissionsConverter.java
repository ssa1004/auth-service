package com.example.auth.adapter.in.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

/**
 * JWT 의 {@code roles} + {@code permissions} claim 을 Spring Security 의
 * GrantedAuthority 로 변환. 이렇게 매핑해 두면 {@code @PreAuthorize("hasAuthority('PERMISSION_billing:read')")}
 * 같은 표현식이 동작합니다.
 */
@Component
public class JwtPermissionsConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        List<String> roles = jwt.getClaimAsStringList("roles");
        if (roles != null) {
            for (String role : roles) authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
        List<String> perms = jwt.getClaimAsStringList("permissions");
        if (perms != null) {
            for (String p : perms) authorities.add(new SimpleGrantedAuthority("PERMISSION_" + p));
        }
        return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
    }
}
