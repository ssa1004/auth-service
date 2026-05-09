// 루트 빌드 — 공통 conventions. 각 모듈이 상속받는 공유 설정.
plugins {
    java
    id("org.springframework.boot") version "3.4.1" apply false
    id("io.spring.dependency-management") version "1.1.7" apply false
}

allprojects {
    group = "com.example.auth"
    version = "0.1.0"

    repositories {
        mavenCentral()
    }
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "io.spring.dependency-management")

    java {
        toolchain {
            languageVersion = JavaLanguageVersion.of(21)
        }
    }

    the<io.spring.gradle.dependencymanagement.dsl.DependencyManagementExtension>().apply {
        imports {
            mavenBom("org.springframework.boot:spring-boot-dependencies:3.4.1")
            mavenBom("org.springframework.security:spring-security-bom:6.4.2")
        }
        // Spring Authorization Server 1.4.x 가 Spring Boot 3.4 / Security 6.4 호환.
        dependencies {
            dependency("org.springframework.security:spring-security-oauth2-authorization-server:1.4.1")
            dependency("dev.samstevens.totp:totp:1.7.1")
            dependency("io.github.bucket4j:bucket4j_jdk17-core:8.10.1")
            dependency("io.github.bucket4j:bucket4j-redis:8.10.1")
        }
    }

    dependencies {
        // 모든 모듈 공통: Lombok + JUnit launcher
        "compileOnly"("org.projectlombok:lombok")
        "annotationProcessor"("org.projectlombok:lombok")
        "testCompileOnly"("org.projectlombok:lombok")
        "testAnnotationProcessor"("org.projectlombok:lombok")
        // Gradle 8+ 부터 launcher 가 transitively 안 끌려옴 → 명시
        "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
    }

    tasks.withType<Test> {
        useJUnitPlatform()
        // Testcontainers 통합 테스트가 활성화되었을 때 OOM 방지
        maxHeapSize = "1g"
    }

    tasks.withType<JavaCompile> {
        options.compilerArgs.addAll(listOf("-parameters", "-Xlint:all", "-Xlint:-processing", "-Xlint:-serial"))
        options.encoding = "UTF-8"
    }
}
