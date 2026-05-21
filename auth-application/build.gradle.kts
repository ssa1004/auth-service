// Use Cases + Ports. Spring 의존성은 stereotype + tx 만 (@Service, @Transactional).
// 외부 라이브러리 (DB 드라이버, Redis, Authorization Server 구현체) 직접 의존 금지 — 모두 Port 인터페이스로.
//
// application 도 Kotlin 으로 작성. Spring AOP (@Transactional / @PreAuthorize) 가
// proxy 를 만들 수 있도록 plugin.spring 으로 @Service 클래스를 자동 open 처리한다.
plugins {
    `java-library`
    kotlin("jvm") version "1.9.25"
    kotlin("plugin.spring") version "1.9.25"
}

dependencies {
    api(project(":auth-domain"))
    api("org.springframework:spring-context")        // @Service, @Component
    api("org.springframework:spring-tx")              // @Transactional
    api("org.slf4j:slf4j-api")                       // LoggerFactory.getLogger
    // 비밀번호 해시는 application 계층에서 도메인 정책 (cost=12) 을 강제하므로 PasswordEncoder 의존 허용.
    // 도메인이 아니라 application 에 둠으로써 Spring Security 의존성을 도메인에서 제거.
    api("org.springframework.security:spring-security-crypto")

    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.mockito:mockito-junit-jupiter")
    testImplementation("org.assertj:assertj-core")
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        // 인터페이스 default 메서드를 Java 측에 그대로 노출 (-Xjvm-default=all).
        freeCompilerArgs.add("-Xjvm-default=all")
    }
}
