// e2e — Postgres + Redis 통합 시나리오 (Testcontainers)
plugins {
    java
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
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("org.springframework.boot:spring-boot-testcontainers")
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")
    testImplementation("com.redis:testcontainers-redis:2.2.2")
    testImplementation("org.awaitility:awaitility")
    // 직접 TOTP 코드 생성용 (verify 시나리오 테스트)
    testImplementation("dev.samstevens.totp:totp")
}
