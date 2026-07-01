// 순수 도메인. Spring 의존성 0. JPA 어노테이션도 0. (헥사고날 핵심)
// jakarta.validation 만 허용 — Bean Validation 어노테이션은 표준이고 프레임워크 비의존.
//
// 도메인은 Kotlin 으로 작성하되, Java 호출자 (application / adapter / bootstrap / e2e)
// 가 무변경으로 컴파일되도록 @JvmRecord / @JvmStatic / @get:JvmName 으로 ABI 를 맞춘다.
plugins {
    `java-library`
    kotlin("jvm") version "2.4.0"
}

dependencies {
    api("jakarta.validation:jakarta.validation-api")

    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core")
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        // 인터페이스 default 메서드를 Java 측에 그대로 노출 (-Xjvm-default=all).
        freeCompilerArgs.add("-Xjvm-default=all")
    }
}
