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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
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
@Testcontainers
public abstract class AbstractE2eTest {

    @Container
    static RedisContainer redis = new RedisContainer(DockerImageName.parse("redis:7-alpine"));

    @DynamicPropertySource
    static void redisProps(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
        registry.add("spring.data.redis.url",
                () -> "redis://" + redis.getHost() + ":" + redis.getMappedPort(6379));
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
