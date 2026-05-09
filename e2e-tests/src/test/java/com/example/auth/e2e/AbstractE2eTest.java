package com.example.auth.e2e;

import com.example.auth.application.port.out.RateLimiter;
import com.example.auth.application.port.out.VerificationMailSender;
import com.example.auth.bootstrap.AuthServiceApplication;
import com.redis.testcontainers.RedisContainer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.utility.DockerImageName;

/**
 * 모든 e2e 테스트의 공통 부팅 — Postgres + Redis 컨테이너 + 실제 Spring Boot.
 *
 * <p>Postgres 는 e2e application.yml 의 {@code jdbc:tc:postgresql:16-alpine:///auth}
 * URL 로 자동 기동, Redis 는 RedisContainer + DynamicPropertySource 로 주입.
 *
 * <p>RateLimiter 와 MailSender 만 in-memory 로 교체 — 실 SMTP 호출 회피.
 */
@SpringBootTest(
        classes = {AuthServiceApplication.class, AbstractE2eTest.E2eOverrides.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@org.springframework.test.context.ActiveProfiles("e2e")
public abstract class AbstractE2eTest {

    /**
     * JVM-singleton — Spring Test 의 @ContextCache 는 클래스마다 캐시 키가 다르므로 각
     * 클래스가 별도 RedisContainer 를 띄우면 재사용된 컨텍스트의 Redis URL 이 stale 해집니다.
     * 컨테이너를 한 번만 시작하고 모든 e2e 클래스가 같은 redis 를 공유합니다 (JVM 종료 시
     * Ryuk 가 정리).
     */
    static final RedisContainer REDIS;

    static {
        REDIS = new RedisContainer(DockerImageName.parse("redis:7-alpine"));
        REDIS.start();
    }

    @DynamicPropertySource
    static void redisProps(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("spring.data.redis.url",
                () -> "redis://" + REDIS.getHost() + ":" + REDIS.getMappedPort(6379));
    }

    @LocalServerPort
    protected int port;

    protected String baseUrl() {
        return "http://localhost:" + port;
    }

    @TestConfiguration
    static class E2eOverrides {

        /**
         * RateLimiter 는 e2e 에서 항상 통과하는 stub. rate limit 자체는 LoginServiceTest
         * 단위 테스트에서 검증됨.
         */
        @Bean
        @Primary
        public RateLimiter testRateLimiter() {
            return key -> true;
        }

        /** SMTP 호출 회피. */
        @Bean
        @Primary
        public VerificationMailSender testMailSender() {
            return (email, link) -> { /* no-op for e2e */ };
        }
    }
}
