// Inbound adapter — REST controllers (회원가입 / 로그인 / MFA / refresh / session 관리 / 운영 RBAC)
// + Spring Authorization Server endpoints (/oauth2/token, /oauth2/jwks, /.well-known/openid-configuration).
//
// Kotlin 마이그레이션 — controller / DTO / security helper / exception handler 모두 Kotlin.
// plugin.spring 이 @Controller / @Component / @ControllerAdvice 가 붙은 class 를 자동 open 처리해
// CGLIB proxy 가 가능하게 한다.
plugins {
    `java-library`
    kotlin("jvm")
    kotlin("plugin.spring")
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

    // Kotlin null-safety 와 호환되는 Jackson module — Kotlin data class 의 non-null 필드를 인식해
    // Instant / Enum / record 역직렬화가 정상 동작한다.
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")

    // Spring Data 가 Kotlin class 의 PreferredConstructorDiscoverer 를 호출할 때 reflect 필요.
    runtimeOnly("org.jetbrains.kotlin:kotlin-reflect")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    // Mockito Kotlin helpers — any() / whenever / verify 의 Kotlin friendly DSL.
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
