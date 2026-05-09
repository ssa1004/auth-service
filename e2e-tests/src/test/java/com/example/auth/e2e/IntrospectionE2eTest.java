package com.example.auth.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.application.port.out.RefreshTokenRepository;
import com.example.auth.application.port.out.TenantRepository;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.token.RefreshToken;
import com.example.auth.domain.token.TokenHasher;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * RFC 7662 Token Introspection 의 표준 응답 형식 + revoke 즉시 반영 검증.
 *
 * <p>시나리오:
 * 1. 회원가입 + 로그인으로 access / refresh 발급
 * 2. /oauth2/introspect 로 access token 조회 → active=true + 표준 claim
 * 3. /oauth2/introspect 로 refresh token 조회 → active=true
 * 4. refresh 를 직접 revoke (admin 모드 simulation) 후 다시 introspect → active=false
 * 5. 호출에 client_secret_basic 인증이 없으면 401
 * 6. 외부에서 만든 가짜 token → active=false (정보 누설 X)
 */
class IntrospectionE2eTest extends AbstractE2eTest {

    @Autowired TenantRepository tenantRepository;
    @Autowired RefreshTokenRepository refreshTokenRepository;

    private final HttpClient http = HttpClient.newHttpClient();

    private static final String CLIENT_ID = "internal-service";
    private static final String CLIENT_SECRET = "internal-service-secret-change-me";

    @BeforeEach
    void seedTenant() {
        if (tenantRepository.findBySlug("acme").isEmpty()) {
            tenantRepository.save(Tenant.create("acme", "ACME", Instant.now()));
        }
    }

    @Test
    void introspect_는_RFC_7662_표준_응답을_반환하고_revoke_즉시_반영() throws Exception {
        // 1) register + login
        String email = "introspect+" + System.nanoTime() + "@example.com";
        post("/api/v1/auth/register", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234"}
                """.formatted(email));

        HttpResponse<String> login = post("/api/v1/auth/login", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234","deviceLabel":"e2e-introspect"}
                """.formatted(email));
        assertThat(login.statusCode()).isEqualTo(200);
        String access = json(login.body(), "accessToken");
        String refresh = json(login.body(), "refreshToken");

        // 2) access token introspect
        HttpResponse<String> accessRes = introspect("token=" + urlEncode(access)
                + "&token_type_hint=access_token");
        assertThat(accessRes.statusCode()).isEqualTo(200);
        String accessBody = accessRes.body();
        // RFC 7662 §2.2 표준 필드
        assertThat(accessBody).contains("\"active\":true");
        assertThat(accessBody).contains("\"token_type\":\"Bearer\"");
        assertThat(accessBody).contains("\"sub\":");
        assertThat(accessBody).contains("\"tnt\":");
        assertThat(accessBody).contains("\"iss\":");
        assertThat(accessBody).contains("\"exp\":");
        assertThat(accessBody).contains("\"iat\":");
        assertThat(accessBody).contains("\"jti\":");

        // 3) refresh token introspect
        HttpResponse<String> refreshRes = introspect("token=" + urlEncode(refresh)
                + "&token_type_hint=refresh_token");
        assertThat(refreshRes.statusCode()).isEqualTo(200);
        assertThat(refreshRes.body()).contains("\"active\":true");

        // 4) refresh 를 admin revoke 한 것처럼 직접 status 변경 → 다시 introspect
        var rt = refreshTokenRepository.findByTokenHashReadOnly(TokenHasher.sha256(refresh)).orElseThrow();
        refreshTokenRepository.save(rt.markRevokedByAdmin(Instant.now()));

        HttpResponse<String> afterRevoke = introspect("token=" + urlEncode(refresh)
                + "&token_type_hint=refresh_token");
        assertThat(afterRevoke.statusCode()).isEqualTo(200);
        assertThat(afterRevoke.body()).contains("\"active\":false");
        // 정보 누설 방지 — sub / tnt 같은 필드는 응답에 없어야 함.
        assertThat(afterRevoke.body()).doesNotContain("\"sub\":");
        assertThat(afterRevoke.body()).doesNotContain("\"tnt\":");

        // 5) client 인증 없이 호출 → 401
        HttpResponse<String> unauth = http.send(HttpRequest.newBuilder(URI.create(baseUrl() + "/oauth2/introspect"))
                        .timeout(Duration.ofSeconds(30))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString("token=" + urlEncode(access)))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(unauth.statusCode()).isEqualTo(401);

        // 6) 가짜 token 도 active=false (정보 누설 차단)
        HttpResponse<String> fake = introspect("token=" + urlEncode("not-a-real-token-at-all"));
        assertThat(fake.statusCode()).isEqualTo(200);
        assertThat(fake.body()).contains("\"active\":false");
    }

    private HttpResponse<String> introspect(String formBody) throws Exception {
        String basic = Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes());
        return http.send(HttpRequest.newBuilder(URI.create(baseUrl() + "/oauth2/introspect"))
                        .timeout(Duration.ofSeconds(30))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .header("Authorization", "Basic " + basic)
                        .POST(HttpRequest.BodyPublishers.ofString(formBody))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
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
        String prefix = "\"" + key + "\":\"";
        int start = body.indexOf(prefix);
        if (start < 0) return null;
        start += prefix.length();
        int end = body.indexOf("\"", start);
        return end < 0 ? null : body.substring(start, end);
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }
}
