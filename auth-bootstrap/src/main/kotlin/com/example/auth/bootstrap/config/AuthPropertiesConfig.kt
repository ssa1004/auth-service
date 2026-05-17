package com.example.auth.bootstrap.config

import com.example.auth.application.security.AuthProperties
import java.net.URI
import java.time.Clock
import java.time.Duration
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * application.yml 의 `auth.*` prefix 를 [AuthProperties] 로 바인딩.
 *
 * `@ConfigurationProperties` 가 record 를 직접 바인딩하기 위해 별도 record 형태의 입력을
 * 받고 [AuthProperties] 로 변환합니다.
 */
@Configuration
open class AuthPropertiesConfig {

    @Bean
    @ConfigurationProperties(prefix = "auth")
    open fun authPropertiesBinding(): AuthPropertiesBinding = AuthPropertiesBinding()

    @Bean
    open fun authProperties(b: AuthPropertiesBinding): AuthProperties {
        val opa = b.opa ?: AuthPropertiesBinding.OpaBinding()
        return AuthProperties(
            b.accessTokenTtl ?: Duration.ofMinutes(15),
            b.refreshTokenTtl ?: Duration.ofDays(30),
            b.refreshReuseGracePeriod ?: Duration.ofSeconds(5),
            if (b.bcryptCost > 0) b.bcryptCost else 12,
            if (b.loginRateBurst > 0) b.loginRateBurst else 10,
            b.loginRateWindow ?: Duration.ofMinutes(1),
            b.jwtIssuer ?: "https://auth.example.com",
            b.mfaIssuer ?: "auth-service",
            b.trustedProxies?.toList() ?: emptyList(),
            AuthProperties.Opa(
                opa.mode ?: "embedded",
                opa.baseUrl,
                opa.callTimeout ?: Duration.ofMillis(100),
            ),
        )
    }

    @Bean
    open fun systemClock(): Clock = Clock.systemUTC()

    /** Spring Boot 가 record 보다 setter-기반 POJO 를 더 잘 다뤄 변환용 클래스 사용. */
    class AuthPropertiesBinding {
        var accessTokenTtl: Duration? = null
        var refreshTokenTtl: Duration? = null
        var refreshReuseGracePeriod: Duration? = null
        var bcryptCost: Int = 0
        var loginRateBurst: Int = 0
        var loginRateWindow: Duration? = null
        var jwtIssuer: String? = null
        var mfaIssuer: String? = null
        var trustedProxies: List<String>? = null
        var opa: OpaBinding? = null

        class OpaBinding {
            var mode: String? = null
            var baseUrl: URI? = null
            var callTimeout: Duration? = null
        }
    }
}
