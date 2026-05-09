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
    // 자체 발행한 JWT 를 *우리 운영 endpoint* (/me/sessions, /admin) 에서 검증할 때 사용.
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")

    // OAuth2 Authorization Server — /oauth2/token /oauth2/jwks /.well-known/openid-configuration 자동 노출
    implementation("org.springframework.security:spring-security-oauth2-authorization-server")

    // OpenAPI — Spring Boot 3.4 / Spring 6.2 와 ControllerAdviceBean signature 호환되는 2.7.0+ 필수.
    // 2.6.0 은 NoSuchMethodError 발생 (GenericResponseService 가 6.1 시그니처 호출).
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.7.0")

    // Tracing / Metrics
    implementation("io.micrometer:micrometer-tracing")
    implementation("io.micrometer:micrometer-core")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
}
