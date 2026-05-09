package com.example.auth.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.application.port.out.TenantRepository;
import com.example.auth.domain.tenant.Tenant;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 실 Postgres + Redis + 전체 부팅된 Spring + REST 호출.
 *
 * <p>시나리오:
 * 1. POST /api/v1/auth/register 로 신규 사용자 가입
 * 2. POST /api/v1/auth/login 으로 access + refresh 발급
 * 3. POST /api/v1/auth/refresh 로 회전
 * 4. 회전된 token 을 다시 보내 reuse detection → 401
 */
class RegisterAndLoginE2eTest extends AbstractE2eTest {

    @Autowired TenantRepository tenantRepository;

    private final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void seedTenant() {
        if (tenantRepository.findBySlug("acme").isEmpty()) {
            tenantRepository.save(Tenant.create("acme", "ACME", Instant.now()));
        }
    }

    @Test
    void 회원가입_로그인_refresh_회전_그리고_reuse_detection_까지() throws Exception {
        // 1) register
        HttpResponse<String> reg = post("/api/v1/auth/register", """
                {"tenantSlug":"acme","email":"e2e+%d@example.com","password":"longenoughpw1234"}
                """.formatted(System.nanoTime()));
        assertThat(reg.statusCode()).isEqualTo(201);
        String email = json(reg.body(), "userId") != null
                ? extract(reg.request().bodyPublisher().toString(), "email")
                : "";

        // 같은 사용자로 로그인 — request body 에서 email 을 꺼내기 위해 body 를 재구성.
        // 단순화: 새로 register 하지 않고, 같은 email 로 즉시 로그인.
        String userEmail = "e2e+login@example.com";
        post("/api/v1/auth/register", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234"}
                """.formatted(userEmail));

        // 2) login
        HttpResponse<String> login = post("/api/v1/auth/login", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234","deviceLabel":"e2e"}
                """.formatted(userEmail));
        assertThat(login.statusCode()).isEqualTo(200);
        String access = json(login.body(), "accessToken");
        String refresh = json(login.body(), "refreshToken");
        assertThat(access).startsWith("ey");
        assertThat(refresh).isNotBlank();

        // 3) refresh 정상 회전
        HttpResponse<String> rotated = post("/api/v1/auth/refresh", """
                {"refreshToken":"%s"}
                """.formatted(refresh));
        assertThat(rotated.statusCode()).isEqualTo(200);
        String newRefresh = json(rotated.body(), "refreshToken");
        assertThat(newRefresh).isNotEqualTo(refresh);

        // 4) 회전된 refresh 를 다시 사용 → reuse detection
        HttpResponse<String> reuse = post("/api/v1/auth/refresh", """
                {"refreshToken":"%s"}
                """.formatted(refresh));
        assertThat(reuse.statusCode()).isEqualTo(401);
        assertThat(reuse.body()).contains("refresh_reuse_detected");

        // 5) 새 refresh 도 사용 불가 (모든 세션 강제 revoke 됨)
        HttpResponse<String> afterReuse = post("/api/v1/auth/refresh", """
                {"refreshToken":"%s"}
                """.formatted(newRefresh));
        assertThat(afterReuse.statusCode()).isEqualTo(401);
    }

    private HttpResponse<String> post(String path, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(baseUrl() + path))
                        .timeout(Duration.ofSeconds(60))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String json(String body, String key) {
        // 매우 단순한 JSON 파서 — 따옴표로 감싼 값만 추출. e2e 검증 용도로만.
        String prefix = "\"" + key + "\":\"";
        int start = body.indexOf(prefix);
        if (start < 0) return null;
        start += prefix.length();
        int end = body.indexOf("\"", start);
        if (end < 0) return null;
        return body.substring(start, end);
    }

    private static String extract(String body, String key) {
        return body;
    }
}
