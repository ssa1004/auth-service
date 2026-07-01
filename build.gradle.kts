// 루트 빌드 — 공통 conventions. 각 모듈이 상속받는 공유 설정.
plugins {
    java
    id("org.springframework.boot") version "4.1.0" apply false
    id("io.spring.dependency-management") version "1.1.7" apply false
    // domain / application / adapter 가 Kotlin. 적용은 각 모듈 build.gradle.kts 에서만.
    // 버전은 auth-domain / auth-application 기존 선언 (1.9.25) 과 정렬.
    kotlin("jvm") version "2.4.0" apply false
    // plugin.spring — @Component / @Controller / @Service 등 Spring 어노테이션 class 를 자동
    //                  open 처리해 CGLIB proxy 가능하게 한다. application / adapter-in / adapter-out 에 적용.
    kotlin("plugin.spring") version "2.4.0" apply false
    // plugin.jpa — @Entity 가 붙은 class 에 no-arg constructor 합성. adapter-out 만 사용.
    kotlin("plugin.jpa") version "2.4.0" apply false
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
            mavenBom("org.springframework.boot:spring-boot-dependencies:4.1.0")
            mavenBom("org.springframework.security:spring-security-bom:7.1.0")
        }
        // Spring Authorization Server 1.5.x 가 Spring Boot 3.5 / Security 6.5 호환.
        dependencies {
            dependency("org.springframework.security:spring-security-oauth2-authorization-server:7.1.0")
            dependency("dev.samstevens.totp:totp:1.7.1")
            dependency("com.bucket4j:bucket4j_jdk17-core:8.19.0")
            dependency("com.bucket4j:bucket4j_jdk17-lettuce:8.19.0")

            // ── 보안: Trivy image 게이트(HIGH/CRITICAL, ignore-unfixed)가 잡은
            //         고칠 수 있는 transitive CVE 를 fixed 최소 버전으로 상향 ──
            // io.spring.dependency-management 의 explicit dependency() override 는
            // import 된 Spring Boot BOM 버전(및 BOM 의 version-property)을 항상 이긴다.
            // (BOM 을 추가 import 하는 방식은 Spring Boot BOM 의 version-property 우선순위에
            //  밀려 OTel 에 적용되지 않아 per-artifact override 를 쓴다.)

            // commons-lang3 3.17.0 → CVE-2025-48924: ClassUtils.getClass 무제한 재귀로
            // StackOverflowError(DoS). 3.18.0 에서 수정.
            dependency("org.apache.commons:commons-lang3:3.20.0")

            // nimbus-jose-jwt — adapter-out 직접 사용(JWK/RS256). SAS/oauth2-jose transitive
            // 가 9.47 로 끌어올리나 advisory vulnerable 범위(CVE-2025-53864, 깊게 중첩된 JSON
            // claim 무제한 재귀 DoS). 9.x 패치(9.37.4)는 9.47 보다 낮아 다운그레이드라 부적합
            // → 다음 fixed 인 10.0.2. 사용 API(JWK/JWKSet/RSAKey/RSAKeyGenerator/SignedJWT/
            // DefaultJWTProcessor 등)는 9.x→10.x 호환(10.x Java 11+, 본 프로젝트 JDK21 충족).
            dependency("com.nimbusds:nimbus-jose-jwt:10.9.1")

            // OpenTelemetry family — CVE-2026-45292: baggage 파싱 무제한 메모리/CPU
            // (opentelemetry-api + opentelemetry-extension-trace-propagators). 1.62.0 에서 수정.
            // OTel 8개 아티팩트는 한 릴리스로 함께 테스트되므로 전부 1.62.0 으로 정렬해
            // 버전 skew(LinkageError/NoSuchMethodError)를 피한다.
            dependencySet(mapOf("group" to "io.opentelemetry", "version" to "1.63.0")) {
                entry("opentelemetry-api")
                entry("opentelemetry-context")
                entry("opentelemetry-extension-trace-propagators")
                entry("opentelemetry-sdk")
                entry("opentelemetry-sdk-common")
                entry("opentelemetry-sdk-logs")
                entry("opentelemetry-sdk-metrics")
                entry("opentelemetry-sdk-trace")
            }
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
        val springBootBom = platform("org.springframework.boot:spring-boot-dependencies:4.1.0")
        val springSecurityBom = platform("org.springframework.security:spring-security-bom:7.1.0")
        // OTel BOM 도 네이티브 platform 으로 — variant-aware 재해석/집계 configuration 까지
        // 1.62.0 이 전파되도록(CVE-2026-45292). dependency-management imports 만으로는
        // 진짜 Gradle constraint 가 안 생겨 일부 변형에서 1.49.0 으로 되돌아갈 수 있다.
        val otelBom = platform("io.opentelemetry:opentelemetry-bom:1.63.0")
        // 모든 의존 버킷 configuration 에 platform constraint 를 건다.
        // api 는 java-library 적용 모듈에만 존재하므로 findByName 으로 가드.
        listOf("api", "implementation", "testImplementation").forEach { bucket ->
            configurations.findByName(bucket)?.let {
                add(bucket, springBootBom)
                add(bucket, springSecurityBom)
                add(bucket, otelBom)
            }
        }
        // BOM 에 없는(직접 관리하던) 좌표는 constraint 로 버전을 고정해 집계 해석을 보장.
        constraints {
            listOf("api", "implementation").forEach { bucket ->
                if (configurations.findByName(bucket) != null) {
                    add(bucket, "org.springframework.security:spring-security-oauth2-authorization-server:7.1.0")
                    add(bucket, "dev.samstevens.totp:totp:1.7.1")
                    add(bucket, "com.bucket4j:bucket4j_jdk17-core:8.19.0")
                    add(bucket, "com.bucket4j:bucket4j_jdk17-lettuce:8.19.0")

                    // ── 보안: Trivy image 게이트(HIGH/CRITICAL, ignore-unfixed)가 잡은
                    //         고칠 수 있는 transitive CVE 를 fixed 최소 버전으로 상향 ──
                    // commons-lang3 3.17.0 (Spring Boot BOM 고정) → ClassUtils.getClass 무제한
                    // 재귀로 StackOverflowError(DoS). 3.18.0 에서 수정.
                    add(bucket, "org.apache.commons:commons-lang3:3.20.0") {
                        because("CVE-2025-48924: uncontrolled recursion in ClassUtils, fixed in 3.18.0")
                    }
                    // nimbus-jose-jwt — adapter-out 이 9.40 직접 선언하나 SAS/oauth2-jose transitive
                    // 가 9.47 로 끌어올림. 9.47 은 advisory vulnerable 범위에 있고, 9.x 패치
                    // 라인(9.37.4)은 9.47 보다 낮아 다운그레이드라 부적합 → 다음 fixed 인 10.0.2 로.
                    // 사용 API(JWK/JWKSet/RSAKey/RSAKeyGenerator/SignedJWT/DefaultJWTProcessor 등)는
                    // 9.x→10.x 에서 호환(10.x 는 Java 11+ 요구, 본 프로젝트 JDK21 충족).
                    add(bucket, "com.nimbusds:nimbus-jose-jwt:10.9.1") {
                        because("CVE-2025-53864: uncontrolled recursion via deeply nested JSON claim, fixed in 10.0.2")
                    }
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
