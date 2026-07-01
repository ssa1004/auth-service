// Gradle 8+ Foojay 플러그인 — 시스템에 Java 21 미설치 시 자동 다운로드
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "auth-service"

include(
    "auth-domain",
    "auth-application",
    "auth-adapter-in",
    "auth-adapter-out",
    "auth-bootstrap",
    "e2e-tests",
)
