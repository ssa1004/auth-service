package com.example.auth.adapter.`in`.security

import com.example.auth.domain.common.TenantId
import com.example.auth.domain.common.UserId
import org.springframework.core.MethodParameter
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.stereotype.Component
import org.springframework.web.bind.support.WebDataBinderFactory
import org.springframework.web.context.request.NativeWebRequest
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.method.support.ModelAndViewContainer

@Component
class AuthenticatedUserResolver : HandlerMethodArgumentResolver {

    override fun supportsParameter(parameter: MethodParameter): Boolean =
        AuthenticatedUser::class.java.isAssignableFrom(parameter.parameterType)

    override fun resolveArgument(
        parameter: MethodParameter,
        mavContainer: ModelAndViewContainer?,
        webRequest: NativeWebRequest,
        binderFactory: WebDataBinderFactory?,
    ): Any {
        val auth = SecurityContextHolder.getContext().authentication
        val principal = auth?.principal
        check(principal is Jwt) { "인증 컨텍스트가 비어있습니다" }
        return AuthenticatedUser(
            UserId.of(principal.subject),
            TenantId.of(principal.getClaimAsString("tnt")),
        )
    }
}
