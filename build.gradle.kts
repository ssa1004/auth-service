// 루트 빌드 — 공통 conventions. 각 모듈이 상속받는 공유 설정.
plugins {
    java
    id("org.springframework.boot") version "3.5.15" apply false
    id("io.spring.dependency-management") version "1.1.7" apply false
    // domain / application / adapter 가 Kotlin. 적용은 각 모듈 build.gradle.kts 에서만.
    // 버전은 auth-domain / auth-application 기존 선언 (1.9.25) 과 정렬.
    kotlin("jvm") version "1.9.25" apply false
    // plugin.spring — @Component / @Controller / @Service 등 Spring 어노테이션 class 를 자동
    //                  open 처리해 CGLIB proxy 가능하게 한다. application / adapter-in / adapter-out 에 적용.
    kotlin("plugin.spring") version "1.9.25" apply false
    // plugin.jpa — @Entity 가 붙은 class 에 no-arg constructor 합성. adapter-out 만 사용.
    kotlin("plugin.jpa") version "1.9.25" apply false
    // OpenAPI spec build-time export — 실제 적용은 bootstrap 모듈.
    id("org.springdoc.openapi-gradle-plugin") version "1.9.0" apply false
    // 멀티모듈 통합 커버리지 — 각 모듈의 jacoco exec 를 모아 단일 리포트로 합산.
    // (Gradle 내장 플러그인, 버전 불필요)
    `jacoco-report-aggregation`
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
    // 모든 모듈에서 커버리지 데이터(.exec)를 생성 — 루트의 jacoco-report-aggregation 이 합산한다.
    apply(plugin = "jacoco")

    java {
        toolchain {
            languageVersion = JavaLanguageVersion.of(21)
        }
    }

    the<JacocoPluginExtension>().toolVersion = "0.8.12"

    // 모듈별 단독 리포트는 'check' 의존이 아님(빠른 빌드 유지). 집계는 루트 testCodeCoverageReport 가 담당.
    tasks.withType<JacocoReport> {
        reports {
            xml.required.set(true)
            html.required.set(true)
        }
    }

    the<io.spring.gradle.dependencymanagement.dsl.DependencyManagementExtension>().apply {
        imports {
            mavenBom("org.springframework.boot:spring-boot-dependencies:3.5.15")
            mavenBom("org.springframework.security:spring-security-bom:6.5.11")
        }
        // Spring Authorization Server 1.5.x 가 Spring Boot 3.5 / Security 6.5 호환.
        dependencies {
            dependency("org.springframework.security:spring-security-oauth2-authorization-server:1.5.8")
            dependency("dev.samstevens.totp:totp:1.7.1")
            dependency("com.bucket4j:bucket4j_jdk17-core:8.14.0")
            dependency("com.bucket4j:bucket4j_jdk17-lettuce:8.14.0")
        }
    }

    dependencies {
        // Gradle 8+ 부터 launcher 가 transitively 안 끌려옴 → 명시
        "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")

        // ── 통합 커버리지(jacoco-report-aggregation) 호환을 위한 BOM platform 선언 ──
        // io.spring.dependency-management 의 imports{} 는 자신이 아는 컴파일/런타임 configuration
        // 에만 버전을 주입할 뿐, 진짜 Gradle dependency constraint 를 만들지 않는다. 그래서
        // jacoco-report-aggregation 이 만드는 :aggregateCodeCoverageReportResults 가
        // 모듈 런타임 변형(variant)을 variant-aware 로 다시 해석할 때 BOM 버전이 빠져
        // "Could not find org.springframework:spring-tx:." 처럼 version 이 비어 실패한다.
        // 같은 BOM 을 Gradle 네이티브 platform() 으로도 선언하면 모든 configuration 으로
        // 전파되는 실제 constraint 가 생겨 집계 configuration 도 버전을 해석한다.
        // (일반 빌드 동작은 동일 BOM·동일 버전이라 변화 없음.)
        val springBootBom = platform("org.springframework.boot:spring-boot-dependencies:3.5.15")
        val springSecurityBom = platform("org.springframework.security:spring-security-bom:6.5.11")
        // 모든 의존 버킷 configuration 에 platform constraint 를 건다.
        // api 는 java-library 적용 모듈에만 존재하므로 findByName 으로 가드.
        listOf("api", "implementation", "testImplementation").forEach { bucket ->
            configurations.findByName(bucket)?.let {
                add(bucket, springBootBom)
                add(bucket, springSecurityBom)
            }
        }
        // BOM 에 없는(직접 관리하던) 좌표는 constraint 로 버전을 고정해 집계 해석을 보장.
        constraints {
            listOf("api", "implementation").forEach { bucket ->
                if (configurations.findByName(bucket) != null) {
                    add(bucket, "org.springframework.security:spring-security-oauth2-authorization-server:1.5.8")
                    add(bucket, "dev.samstevens.totp:totp:1.7.1")
                    add(bucket, "com.bucket4j:bucket4j_jdk17-core:8.14.0")
                    add(bucket, "com.bucket4j:bucket4j_jdk17-lettuce:8.14.0")
                }
            }
        }
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

// ── 통합 커버리지 ──────────────────────────────────────────────────────────────
// jacoco-report-aggregation 이 아래 모듈들의 test exec 데이터를 모아 단일 HTML/XML 로 합산.
// 실행:  ./gradlew testCodeCoverageReport
// 출력:  build/reports/jacoco/testCodeCoverageReport/  (html/ + testCodeCoverageReport.xml)
// 주의:  adapter-out / bootstrap / e2e 테스트는 Testcontainers(Postgres/Redis)를 띄우므로
//        전체 합산 리포트는 Docker 가 필요하다. domain/application 만 보려면 각 모듈 test 후
//        해당 모듈 jacocoTestReport 를 본다.
dependencies {
    jacocoAggregation(project(":auth-domain"))
    jacocoAggregation(project(":auth-application"))
    jacocoAggregation(project(":auth-adapter-in"))
    jacocoAggregation(project(":auth-adapter-out"))
    jacocoAggregation(project(":auth-bootstrap"))
    jacocoAggregation(project(":e2e-tests"))
}

// jacoco-report-aggregation 이 위 jacocoAggregation 의존을 보고 'testCodeCoverageReport'
// 태스크를 자동 등록한다. XML 리포트를 기본 활성화해 외부 배지/SonarQube 가 읽을 수 있게 한다.
tasks.withType<JacocoReport>().configureEach {
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}
