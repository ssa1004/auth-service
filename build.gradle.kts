// 루트 빌드 — 공통 conventions. 각 모듈이 상속받는 공유 설정.
plugins {
    java
    id("org.springframework.boot") version "4.0.6" apply false
    id("io.spring.dependency-management") version "1.1.7" apply false
    // domain / application / adapter 가 Kotlin. 적용은 각 모듈 build.gradle.kts 에서만.
    // 버전은 auth-domain / auth-application 기존 선언 (1.9.25) 과 정렬.
    kotlin("jvm") version "1.9.25" apply false
    // plugin.spring — @Component / @Controller / @Service 등 Spring 어노테이션 class 를 자동
    //                  open 처리해 CGLIB proxy 가능하게 한다. application / adapter-in / adapter-out 에 적용.
    kotlin("plugin.spring") version "1.9.25" apply false
    // plugin.jpa — @Entity 가 붙은 class 에 no-arg constructor 합성. adapter-out 만 사용.
    kotlin("plugin.jpa") version "1.9.25" apply false
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
            mavenBom("org.springframework.boot:spring-boot-dependencies:4.0.6")
            mavenBom("org.springframework.security:spring-security-bom:7.0.5")
        }
        // Spring Authorization Server 1.4.x 가 Spring Boot 3.4 / Security 6.4 호환.
        dependencies {
            dependency("org.springframework.security:spring-security-oauth2-authorization-server:7.0.5")
            dependency("dev.samstevens.totp:totp:1.7.1")
            dependency("com.bucket4j:bucket4j_jdk17-core:8.14.0")
            dependency("com.bucket4j:bucket4j_jdk17-lettuce:8.14.0")
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
