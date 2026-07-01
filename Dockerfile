# --- Build stage ---
# 베이스 이미지는 digest 로 고정 — 동일 태그가 가리키는 이미지가 바뀌어도 재현 가능한 빌드 보장.
# 태그 주석은 사람이 읽기 위한 것이며, dependabot(docker) 가 digest 를 갱신한다.
FROM eclipse-temurin:25-jdk-alpine@sha256:5ecfde8e5ecde5954ea3721155b345ef56c1d579b940c761318ad4c05959a151 AS build
WORKDIR /workspace
COPY gradle gradle
COPY gradlew settings.gradle.kts build.gradle.kts gradle.properties ./
COPY auth-domain/build.gradle.kts auth-domain/build.gradle.kts
COPY auth-application/build.gradle.kts auth-application/build.gradle.kts
COPY auth-adapter-out/build.gradle.kts auth-adapter-out/build.gradle.kts
COPY auth-adapter-in/build.gradle.kts auth-adapter-in/build.gradle.kts
COPY auth-bootstrap/build.gradle.kts auth-bootstrap/build.gradle.kts
COPY e2e-tests/build.gradle.kts e2e-tests/build.gradle.kts
RUN ./gradlew --no-daemon dependencies --quiet || true

COPY . .
RUN ./gradlew --no-daemon :auth-bootstrap:bootJar -x test

# --- Runtime stage ---
FROM eclipse-temurin:25-jre-alpine@sha256:28db6fdf60e38945e43d840c0333aeaec66c15943070104f7586fd3c9d1665b0 AS runtime

# OCI image labels — 출처 / 라이선스 / 리비전 추적. revision/created 는 빌드 시 주입.
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="auth-service" \
      org.opencontainers.image.description="OAuth2 / OIDC IdP — JWT, JWK rotation, refresh rotation, 2FA, audit" \
      org.opencontainers.image.source="https://github.com/ssa1004/auth-service" \
      org.opencontainers.image.url="https://github.com/ssa1004/auth-service" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="ssa1004" \
      org.opencontainers.image.base.name="docker.io/library/eclipse-temurin:21-jre-alpine" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# 베이스 이미지의 OS 패키지를 최신 보안 패치로 갱신 (alpine apk). 캐시는 남기지 않음.
RUN apk upgrade --no-cache

RUN addgroup -S auth && adduser -S auth -G auth
WORKDIR /app
COPY --from=build /workspace/auth-bootstrap/build/libs/auth-bootstrap-*-boot.jar /app/app.jar
RUN chown -R auth:auth /app
USER auth

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8080/actuator/health/liveness || exit 1

ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseG1GC -XX:+ExitOnOutOfMemoryError"
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
