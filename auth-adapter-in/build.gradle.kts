// Inbound adapter — REST controllers (회원가입 / 로그인 / MFA / refresh / session 관리 / 운영 RBAC)
// + Spring Authorization Server endpoints (/oauth2/token, /oauth2/jwks, /.well-known/openid-configuration).
plugins {
    `java-library`
}

dependencies {
    implementation(project(":auth-application"))

    // Web
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-security")

    // OAuth2 Authorization Server — /oauth2/token /oauth2/jwks /.well-known/openid-configuration 자동 노출
    implementation("org.springframework.security:spring-security-oauth2-authorization-server")

    // OpenAPI
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.6.0")

    // Tracing / Metrics
    implementation("io.micrometer:micrometer-tracing")
    implementation("io.micrometer:micrometer-core")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
}
