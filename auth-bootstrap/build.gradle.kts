// Spring Boot 진입점. main + 통합 config + JWK rotation 스케줄러.
//
// Kotlin 마이그레이션 — AuthServiceApplication / JwkConfig / SecurityConfig / OIDC wiring 모두 Kotlin.
// plugin.spring 은 @Configuration / @Component class 의 open 처리, JWK / readiness coordinator 같은
// proxy 대상 빈이 CGLIB 로 감싸질 수 있게 한다.
plugins {
    `java-library`
    kotlin("jvm")
    kotlin("plugin.spring")
    id("org.springframework.boot")
    id("io.spring.dependency-management")
    // OpenAPI spec build-time export — generateOpenApiDocs 가 앱을 부팅한 뒤
    // /v3/api-docs 를 fetch 해 docs/openapi/auth-service.yaml 로 떨어뜨린다.
    id("org.springdoc.openapi-gradle-plugin")
}

dependencies {
    implementation(project(":auth-domain"))
    implementation(project(":auth-application"))
    implementation(project(":auth-adapter-in"))
    implementation(project(":auth-adapter-out"))

    // Bootstrap 자체에서 사용하는 starter 들
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")    // DataSource auto-config
    implementation("org.springframework.boot:spring-boot-starter-data-redis")   // RedisTemplate
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.security:spring-security-oauth2-authorization-server")
    // OAuth2 client — Google OIDC consumer (ADR-0013).
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client")

    // Actuator / Prometheus
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("io.micrometer:micrometer-registry-prometheus")
    implementation("io.micrometer:micrometer-tracing-bridge-otel")

    // JWK rotation — Nimbus JOSE 는 spring-security-oauth2-authorization-server 가 transitive 로 가져옴.
    // 명시적으로 다시 의존하지 않아도 컴파일 가능.

    // Kotlin null-safety 와 호환되는 Jackson module — @ConfigurationProperties 바인딩 시 Kotlin
    // data class 의 nullability / default value 를 인식한다.
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")

    // Spring Boot 가 Kotlin data class 의 PreferredConstructorDiscoverer 를 호출할 때 reflect 필요.
    runtimeOnly("org.jetbrains.kotlin:kotlin-reflect")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
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

tasks.named("bootJar") {
    enabled = true
}

// e2e-tests 가 AuthServiceApplication 클래스를 import 할 수 있도록 plain jar 도 활성화.
tasks.named<Jar>("jar") {
    enabled = true
    archiveClassifier.set("")
}

tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    archiveClassifier.set("boot")
}

// OpenAPI spec export 설정 — ./gradlew :auth-bootstrap:generateOpenApiDocs.
// 플러그인이 bootRun 으로 앱을 띄우고 apiDocsUrl 을 fetch 해 outputFileName 으로 저장한다.
// 앱 부팅에 Postgres / Redis 가 필요하므로 로컬 단독 실행보다는 CI 에서 docker compose 와
// 함께 돌리는 것을 권장 (docs/openapi/README.md 참고).
openApi {
    apiDocsUrl.set("http://localhost:8080/v3/api-docs.yaml")
    outputDir.set(layout.projectDirectory.dir("../docs/openapi"))
    outputFileName.set("auth-service.yaml")
    waitTimeInSeconds.set(120)
}
