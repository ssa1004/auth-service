// Outbound adapter — JPA (User / Tenant / Role / RefreshToken / MfaSecret / AuditLog),
// Redis (refresh token reuse 감지 + rate limit token bucket), TOTP, 메일 전송 (mock for verification).
//
// Kotlin 마이그레이션 — entity / repository / adapter / 외부 client 모두 Kotlin.
// plugin.spring 은 @Repository / @Component 의 open 처리, plugin.jpa 는 @Entity 의 no-arg constructor 합성을 담당.
plugins {
    `java-library`
    kotlin("jvm")
    kotlin("plugin.spring")
    kotlin("plugin.jpa")
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
    implementation("com.bucket4j:bucket4j_jdk17-core")
    implementation("com.bucket4j:bucket4j_jdk17-lettuce")

    // JWT 서명 — Spring Authorization Server 가 동일 라이브러리를 transitive 로 가져오지만
    // adapter-out 에서 직접 import 하므로 명시적 선언이 필요합니다.
    implementation("com.nimbusds:nimbus-jose-jwt:9.40")

    // RFC 7662 introspection 시 자체 발행 access JWT 를 디코드 — JwtDecoder API 사용 (ADR-0017).
    implementation("org.springframework.security:spring-security-oauth2-jose")
    implementation("org.springframework.security:spring-security-oauth2-resource-server")

    // 2FA TOTP — RFC 6238. Google Authenticator 호환. dev.samstevens.totp 가 단순/검증된 라이브러리.
    implementation("dev.samstevens.totp:totp")

    // 비밀번호 해시 BCrypt. application 모듈에 이미 spring-security-crypto api 노출됨.
    implementation("org.springframework.security:spring-security-crypto")

    // 메일 (verification 토큰 발송) — Mailhog SMTP 로 mock.
    implementation("org.springframework.boot:spring-boot-starter-mail")

    // JSON (audit log payload + OPA decision request/response)
    implementation("com.fasterxml.jackson.core:jackson-databind")

    // OPA REST 호출 — Spring 6 RestClient (Java HttpClient blocking) 사용.
    // spring-web 은 spring-boot-starter-data-jpa transitives 에 포함되지 않으므로 명시.
    implementation("org.springframework:spring-web")

    // Kotlin null-safety 와 호환되는 Jackson module — OPA decision request/response, audit payload 직렬화 시
    // Kotlin data class 의 nullability / default value 를 인식한다.
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")

    // Spring Data JPA 가 Kotlin entity / record 의 PreferredConstructorDiscoverer 를 호출할 때 reflect 필요.
    runtimeOnly("org.jetbrains.kotlin:kotlin-reflect")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-testcontainers")
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")
    testImplementation("com.redis:testcontainers-redis:2.2.2")
    // Mockito Kotlin helpers — any() / whenever / verify 의 Kotlin friendly DSL.
    testImplementation("org.mockito.kotlin:mockito-kotlin:6.3.0")
}

kotlin {
    jvmToolchain(21)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}
