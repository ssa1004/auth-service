// e2e — Postgres + Redis 통합 시나리오 (Testcontainers)
//
// Kotlin 마이그레이션 — 모든 테스트 Kotlin 화. plugin.spring 으로 @SpringBootTest / @TestConfiguration
// 의 abstract base 가 open 처리되어 상속 가능.
plugins {
    java
    kotlin("jvm")
    kotlin("plugin.spring")
    id("io.spring.dependency-management")
}

dependencies {
    testImplementation(project(":auth-bootstrap"))
    // bootstrap implementation 의존을 e2e 컴파일에 노출
    testImplementation(project(":auth-domain"))
    testImplementation(project(":auth-application"))
    testImplementation(project(":auth-adapter-out"))
    testImplementation(project(":auth-adapter-in"))

    testImplementation("org.springframework.boot:spring-boot-starter-data-jpa")
    testImplementation("org.springframework.boot:spring-boot-starter-data-redis")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    // OpenAPI spec JSON 파싱 — spring-boot-starter-test 가 transitive 로 가져오지만 직접 import 명시.
    testImplementation("com.fasterxml.jackson.core:jackson-databind")
    testImplementation("org.springframework.security:spring-security-test")
    // JWT 디코드 — JwkRotationE2eTest 에서 회전 전후 access JWT 의 kid 비교.
    testImplementation("org.springframework.security:spring-security-oauth2-jose")
    testImplementation("org.springframework.security:spring-security-oauth2-resource-server")
    testImplementation("org.springframework.boot:spring-boot-testcontainers")
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")
    testImplementation("com.redis:testcontainers-redis:2.2.2")
    testImplementation("org.awaitility:awaitility")
    // 직접 TOTP 코드 생성용 (verify 시나리오 테스트)
    testImplementation("dev.samstevens.totp:totp")

    // Kotlin null-safety 와 호환되는 Jackson module — e2e 테스트의 ObjectMapper 도 Kotlin DTO 인식.
    testImplementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    // Mockito Kotlin helpers — 필요 시 사용.
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
}

kotlin {
    jvmToolchain(21)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}
