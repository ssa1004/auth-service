# --- Build stage ---
FROM eclipse-temurin:21-jdk-alpine AS build
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
FROM eclipse-temurin:21-jre-alpine AS runtime
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
