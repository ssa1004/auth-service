// Use Cases + Ports. Spring 의존성은 stereotype + tx 만 (@Service, @Transactional).
// 외부 라이브러리 (DB 드라이버, Redis, Authorization Server 구현체) 직접 의존 금지 — 모두 Port 인터페이스로.
plugins {
    `java-library`
}

dependencies {
    api(project(":auth-domain"))
    api("org.springframework:spring-context")        // @Service, @Component
    api("org.springframework:spring-tx")              // @Transactional
    api("org.slf4j:slf4j-api")                       // Lombok @Slf4j
    // 비밀번호 해시는 application 계층에서 도메인 정책 (cost=12) 을 강제하므로 PasswordEncoder 의존 허용.
    // 도메인이 아니라 application 에 둠으로써 Spring Security 의존성을 도메인에서 제거.
    api("org.springframework.security:spring-security-crypto")

    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.mockito:mockito-junit-jupiter")
    testImplementation("org.assertj:assertj-core")
}
