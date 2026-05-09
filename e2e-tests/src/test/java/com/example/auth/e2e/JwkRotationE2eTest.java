package com.example.auth.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.adapter.out.security.JwkSourceProvider;
import com.example.auth.application.port.out.TenantRepository;
import com.example.auth.bootstrap.jwk.JwkRotationScheduler;
import com.example.auth.domain.tenant.Tenant;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * JWK rotation 의 실 동작을 ADR-0003 의 시나리오대로 검증.
 *
 * <p>본 테스트가 보장하는 invariant:
 * <ol>
 *   <li>부팅 직후 JWKS endpoint 는 current 1개 키를 노출 (또는 previous 가 디스크에 살아있다면 2개).</li>
 *   <li>회전 1회 후 — JWKS 가 current + previous 두 키를 노출. 회전 *전* 발급된 access JWT
 *       는 *previous* 로 검증 통과 — grace period 의 핵심 보장.</li>
 *   <li>회전 *후* 발급된 새 access JWT 는 *current* 로 검증 통과.</li>
 *   <li>두 token 이 서로 다른 kid 로 서명되어 있음 — JWT header.kid 가 다른지 확인.</li>
 * </ol>
 *
 * <p>JwkRotationScheduler 는 운영에서 cron 24h 주기로 호출되지만, 테스트는 직접 메서드를
 * 호출하여 회전 사이클을 시뮬레이션합니다 — production 코드 수정 없음.
 */
class JwkRotationE2eTest extends AbstractE2eTest {

    @Autowired JwkRotationScheduler rotationScheduler;
    @Autowired JwkSourceProvider jwkSourceProvider;
    @Autowired JwtDecoder jwtDecoder;
    @Autowired TenantRepository tenantRepository;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper om = new ObjectMapper();

    @BeforeEach
    void seedTenant() {
        if (tenantRepository.findBySlug("acme").isEmpty()) {
            tenantRepository.save(Tenant.create("acme", "ACME", Instant.now()));
        }
    }

    @Test
    void 회전_전_발급된_access_토큰은_회전_후에도_grace_period_동안_검증_통과() throws Exception {
        // 1) 회전 전 — JWKS 의 현재 kid 기록.
        Set<String> kidsBeforeRotation = jwksKids();
        assertThat(kidsBeforeRotation).as("부팅 후 JWKS 에 최소 1개 키").isNotEmpty();
        String currentKidBefore = jwkSourceProvider.current().getKeyID();

        // 2) 사용자 로그인 → access JWT 발급. 이 token 은 회전 *전* 키로 서명됨.
        String accessBefore = loginAndGetAccessToken("rotate-before+" + System.nanoTime() + "@example.com");
        Jwt parsedBefore = jwtDecoder.decode(accessBefore);
        String kidBeforeOnToken = parsedBefore.getHeaders().get("kid").toString();
        assertThat(kidBeforeOnToken).isEqualTo(currentKidBefore);

        // 3) 회전 1회 — production scheduler 의 메서드를 그대로 호출.
        rotationScheduler.rotate();

        // 4) JWKS 가 current + previous 두 개를 노출. 회전 전 kid 는 previous 로 보존되어야 함.
        Set<String> kidsAfter = jwksKids();
        assertThat(kidsAfter)
                .as("회전 후 JWKS 에 새 + 직전 kid 두 개")
                .hasSize(2)
                .contains(kidBeforeOnToken)
                .contains(jwkSourceProvider.current().getKeyID());
        assertThat(jwkSourceProvider.current().getKeyID())
                .as("회전 후 current 는 새 kid")
                .isNotEqualTo(kidBeforeOnToken);

        // 5) 회전 *전* 발급된 access JWT 가 여전히 검증 통과 — grace period 의 핵심 보장.
        Jwt reparsed = jwtDecoder.decode(accessBefore);
        assertThat(reparsed.getSubject()).isEqualTo(parsedBefore.getSubject());

        // 6) 회전 *후* 발급한 access JWT 도 검증 통과 + 새 kid 로 서명.
        String accessAfter = loginAndGetAccessToken("rotate-after+" + System.nanoTime() + "@example.com");
        Jwt parsedAfter = jwtDecoder.decode(accessAfter);
        String kidAfter = parsedAfter.getHeaders().get("kid").toString();
        assertThat(kidAfter)
                .as("회전 후 새 token 은 새 kid 로 서명")
                .isEqualTo(jwkSourceProvider.current().getKeyID())
                .isNotEqualTo(kidBeforeOnToken);
    }

    @Test
    void 두_번_회전_후에는_원래_키가_JWKS_에서_사라짐() throws Exception {
        String firstKid = jwkSourceProvider.current().getKeyID();

        rotationScheduler.rotate();
        String secondKid = jwkSourceProvider.current().getKeyID();
        assertThat(secondKid).isNotEqualTo(firstKid);

        rotationScheduler.rotate();
        String thirdKid = jwkSourceProvider.current().getKeyID();
        assertThat(thirdKid).isNotEqualTo(secondKid).isNotEqualTo(firstKid);

        // JWKS 는 third (current) + second (previous) 두 개만. first 는 폐기.
        Set<String> kids = jwksKids();
        assertThat(kids)
                .as("두 번 회전 후 JWKS 는 새 + 직전 두 개만")
                .hasSize(2)
                .contains(thirdKid)
                .contains(secondKid)
                .doesNotContain(firstKid);
    }

    private String loginAndGetAccessToken(String email) throws Exception {
        post("/api/v1/auth/register", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234"}
                """.formatted(email));
        HttpResponse<String> login = post("/api/v1/auth/login", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234","deviceLabel":"jwk-rotation-e2e"}
                """.formatted(email));
        assertThat(login.statusCode()).isEqualTo(200);
        JsonNode body = om.readTree(login.body());
        String access = body.path("accessToken").asText();
        assertThat(access).as("login 응답에 accessToken").isNotBlank();
        return access;
    }

    private Set<String> jwksKids() throws Exception {
        HttpResponse<String> res = http.send(HttpRequest.newBuilder(
                        URI.create(baseUrl() + "/oauth2/jwks")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(res.statusCode()).isEqualTo(200);
        JsonNode keys = om.readTree(res.body()).path("keys");
        Set<String> kids = new HashSet<>();
        for (JsonNode k : keys) kids.add(k.path("kid").asText());
        return kids;
    }

    private HttpResponse<String> post(String path, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(baseUrl() + path))
                        .timeout(Duration.ofSeconds(60))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

}
