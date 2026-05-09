package com.example.auth.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.application.port.out.RefreshTokenRepository;
import com.example.auth.application.port.out.TenantRepository;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.token.RefreshTokenStatus;
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
 * RFC 7009 Token Revocation 의 admin scope 검증 + revoke 후 introspect=active:false 검증.
 *
 * <p>시나리오:
 * 1. register + login → refresh / access 발급
 * 2. internal-admin (token.revoke scope) 으로 /oauth2/revoke 호출 → 200
 * 3. introspect 로 active=false 확인 (revoke 즉시 반영)
 * 4. internal-service (token.revoke 없음) 으로 revoke 시도 → 403
 * 5. 알 수 없는 token revoke → 200 (RFC 7009 §2.2 — 정보 누설 차단)
 * 6. revoke 된 refresh 의 status 가 REVOKED_BY_ADMIN 인지 직접 확인
 */
class RevokeTokenE2eTest extends AbstractE2eTest {

    @Autowired TenantRepository tenantRepository;
    @Autowired RefreshTokenRepository refreshTokenRepository;

    private final HttpClient http = HttpClient.newHttpClient();

    private static final String SVC_CLIENT = "internal-service";
    private static final String SVC_SECRET = "internal-service-secret-change-me";
    private static final String ADMIN_CLIENT = "internal-admin";
    private static final String ADMIN_SECRET = "internal-admin-secret-change-me";

    @BeforeEach
    void seedTenant() {
        if (tenantRepository.findBySlug("acme").isEmpty()) {
            tenantRepository.save(Tenant.create("acme", "ACME", Instant.now()));
        }
    }

    @Test
    void admin_은_refresh_token_을_revoke_하고_introspect_가_즉시_inactive_로_바뀜() throws Exception {
        // 1) register + login
        String email = "revoke+" + System.nanoTime() + "@example.com";
        post("/api/v1/auth/register", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234"}
                """.formatted(email));
        HttpResponse<String> login = post("/api/v1/auth/login", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234","deviceLabel":"e2e-revoke"}
                """.formatted(email));
        assertThat(login.statusCode()).isEqualTo(200);
        String refresh = json(login.body(), "refreshToken");

        // 2) internal-admin 으로 refresh revoke → 200
        HttpResponse<String> revoke = revokeAs(ADMIN_CLIENT, ADMIN_SECRET,
                "token=" + urlEncode(refresh) + "&token_type_hint=refresh_token");
        assertThat(revoke.statusCode()).isEqualTo(200);

        // 3) introspect 로 active=false 확인
        HttpResponse<String> introspect = introspectAs(SVC_CLIENT, SVC_SECRET,
                "token=" + urlEncode(refresh) + "&token_type_hint=refresh_token");
        assertThat(introspect.statusCode()).isEqualTo(200);
        assertThat(introspect.body()).contains("\"active\":false");

        // 4) refresh 가 REVOKED_BY_ADMIN 으로 마킹됐는지 직접 확인
        var rt = refreshTokenRepository.findByTokenHashReadOnly(TokenHasher.sha256(refresh)).orElseThrow();
        assertThat(rt.status()).isEqualTo(RefreshTokenStatus.REVOKED_BY_ADMIN);
    }

    @Test
    void token_revoke_scope_없는_client_는_403() throws Exception {
        String email = "revoke-deny+" + System.nanoTime() + "@example.com";
        post("/api/v1/auth/register", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234"}
                """.formatted(email));
        HttpResponse<String> login = post("/api/v1/auth/login", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234","deviceLabel":"e2e-deny"}
                """.formatted(email));
        String refresh = json(login.body(), "refreshToken");

        // internal-service 는 token.revoke scope 없음 → OPA 거부 → 403
        HttpResponse<String> denied = revokeAs(SVC_CLIENT, SVC_SECRET,
                "token=" + urlEncode(refresh) + "&token_type_hint=refresh_token");
        assertThat(denied.statusCode()).isEqualTo(403);

        // refresh 는 그대로 ACTIVE
        var rt = refreshTokenRepository.findByTokenHashReadOnly(TokenHasher.sha256(refresh)).orElseThrow();
        assertThat(rt.status()).isEqualTo(RefreshTokenStatus.ACTIVE);
    }

    @Test
    void 알_수_없는_token_의_revoke_는_200_정보_누설_차단() throws Exception {
        HttpResponse<String> res = revokeAs(ADMIN_CLIENT, ADMIN_SECRET,
                "token=" + urlEncode("bogus-token-for-rfc7009-spec"));
        assertThat(res.statusCode()).isEqualTo(200);
    }

    @Test
    void 인증_없이_revoke_시도는_401() throws Exception {
        HttpResponse<String> res = http.send(HttpRequest.newBuilder(URI.create(baseUrl() + "/oauth2/revoke"))
                        .timeout(Duration.ofSeconds(30))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString("token=anything"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(res.statusCode()).isEqualTo(401);
    }

    private HttpResponse<String> revokeAs(String clientId, String secret, String formBody) throws Exception {
        return formPost("/oauth2/revoke", clientId, secret, formBody);
    }

    private HttpResponse<String> introspectAs(String clientId, String secret, String formBody) throws Exception {
        return formPost("/oauth2/introspect", clientId, secret, formBody);
    }

    private HttpResponse<String> formPost(String path, String clientId, String secret, String formBody) throws Exception {
        String basic = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes());
        return http.send(HttpRequest.newBuilder(URI.create(baseUrl() + path))
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
