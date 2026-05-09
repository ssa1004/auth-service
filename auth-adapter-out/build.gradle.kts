// Outbound adapter — JPA (User / Tenant / Role / RefreshToken / MfaSecret / AuditLog),
// Redis (refresh token reuse 감지 + rate limit token bucket), TOTP, 메일 전송 (mock for verification).
plugins {
    `java-library`
}

dependencies {
    implementation(project(":auth-application"))

    // Persistence
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.flywaydb:flyway-core")
    runtimeOnly("org.postgresql:postgresql")
    runtimeOnly("com.h2database:h2")
    runtimeOnly("org.flywaydb:flyway-database-postgresql")

    // Cache / KV — refresh rotation, rate-limit, reuse detection 윈도우
    implementation("org.springframework.boot:spring-boot-starter-data-redis")

    // Rate limiting (token bucket — IP+username key)
    implementation("io.github.bucket4j:bucket4j_jdk17-core")
    implementation("io.github.bucket4j:bucket4j-redis")

    // 2FA TOTP — RFC 6238. Google Authenticator 호환. dev.samstevens.totp 가 단순/검증된 라이브러리.
    implementation("dev.samstevens.totp:totp")

    // 비밀번호 해시 BCrypt. application 모듈에 이미 spring-security-crypto api 노출됨.
    implementation("org.springframework.security:spring-security-crypto")

    // 메일 (verification 토큰 발송) — Mailhog SMTP 로 mock.
    implementation("org.springframework.boot:spring-boot-starter-mail")

    // JSON (audit log payload)
    implementation("com.fasterxml.jackson.core:jackson-databind")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-testcontainers")
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")
    testImplementation("com.redis:testcontainers-redis:2.2.2")
}
