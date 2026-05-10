package com.example.auth.bootstrap.config;

import com.example.auth.application.security.AuthProperties;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * application.yml 의 {@code auth.*} prefix 를 {@link AuthProperties} 로 바인딩.
 *
 * <p>{@code @ConfigurationProperties} 가 record 를 직접 바인딩하기 위해 별도 record 형태의
 * 입력을 받고 {@link AuthProperties} 로 변환합니다.
 */
@Configuration
public class AuthPropertiesConfig {

    @Bean
    @ConfigurationProperties(prefix = "auth")
    public AuthPropertiesBinding authPropertiesBinding() {
        return new AuthPropertiesBinding();
    }

    @Bean
    public AuthProperties authProperties(AuthPropertiesBinding b) {
        AuthPropertiesBinding.OpaBinding opa = b.opa != null ? b.opa : new AuthPropertiesBinding.OpaBinding();
        return new AuthProperties(
                b.accessTokenTtl != null ? b.accessTokenTtl : Duration.ofMinutes(15),
                b.refreshTokenTtl != null ? b.refreshTokenTtl : Duration.ofDays(30),
                b.refreshReuseGracePeriod != null ? b.refreshReuseGracePeriod : Duration.ofSeconds(5),
                b.bcryptCost > 0 ? b.bcryptCost : 12,
                b.loginRateBurst > 0 ? b.loginRateBurst : 10,
                b.loginRateWindow != null ? b.loginRateWindow : Duration.ofMinutes(1),
                b.jwtIssuer != null ? b.jwtIssuer : "https://auth.example.com",
                b.mfaIssuer != null ? b.mfaIssuer : "auth-service",
                b.trustedProxies != null ? List.copyOf(b.trustedProxies) : List.of(),
                new AuthProperties.Opa(
                        opa.mode != null ? opa.mode : "embedded",
                        opa.baseUrl,
                        opa.callTimeout != null ? opa.callTimeout : Duration.ofMillis(100)));
    }

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }

    /** Spring Boot 가 record 보다 setter-기반 POJO 를 더 잘 다뤄 변환용 클래스 사용. */
    public static class AuthPropertiesBinding {
        public Duration accessTokenTtl;
        public Duration refreshTokenTtl;
        public Duration refreshReuseGracePeriod;
        public int bcryptCost;
        public int loginRateBurst;
        public Duration loginRateWindow;
        public String jwtIssuer;
        public String mfaIssuer;
        public List<String> trustedProxies;
        public OpaBinding opa;

        public Duration getAccessTokenTtl() { return accessTokenTtl; }
        public void setAccessTokenTtl(Duration v) { this.accessTokenTtl = v; }
        public Duration getRefreshTokenTtl() { return refreshTokenTtl; }
        public void setRefreshTokenTtl(Duration v) { this.refreshTokenTtl = v; }
        public Duration getRefreshReuseGracePeriod() { return refreshReuseGracePeriod; }
        public void setRefreshReuseGracePeriod(Duration v) { this.refreshReuseGracePeriod = v; }
        public int getBcryptCost() { return bcryptCost; }
        public void setBcryptCost(int v) { this.bcryptCost = v; }
        public int getLoginRateBurst() { return loginRateBurst; }
        public void setLoginRateBurst(int v) { this.loginRateBurst = v; }
        public Duration getLoginRateWindow() { return loginRateWindow; }
        public void setLoginRateWindow(Duration v) { this.loginRateWindow = v; }
        public String getJwtIssuer() { return jwtIssuer; }
        public void setJwtIssuer(String v) { this.jwtIssuer = v; }
        public String getMfaIssuer() { return mfaIssuer; }
        public void setMfaIssuer(String v) { this.mfaIssuer = v; }
        public List<String> getTrustedProxies() { return trustedProxies; }
        public void setTrustedProxies(List<String> v) { this.trustedProxies = v; }
        public OpaBinding getOpa() { return opa; }
        public void setOpa(OpaBinding v) { this.opa = v; }

        public static class OpaBinding {
            public String mode;
            public URI baseUrl;
            public Duration callTimeout;

            public String getMode() { return mode; }
            public void setMode(String v) { this.mode = v; }
            public URI getBaseUrl() { return baseUrl; }
            public void setBaseUrl(URI v) { this.baseUrl = v; }
            public Duration getCallTimeout() { return callTimeout; }
            public void setCallTimeout(Duration v) { this.callTimeout = v; }
        }
    }
}
