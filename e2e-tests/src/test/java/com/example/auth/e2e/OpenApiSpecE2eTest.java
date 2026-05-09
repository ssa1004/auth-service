package com.example.auth.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * springdoc 가 노출한 /v3/api-docs JSON 이 controller / OpenApiConfig 의 의도와 일치하는지
 * 검증합니다.
 *
 * <p>spec 의 정확성은 Resource Server 통합의 첫 접촉면 — 개발자가 swagger UI 만 보고도
 * SecurityScheme (bearerAuth / clientBasic), 새 endpoint (RFC 7662 / 7009) 를 즉시 사용
 * 가능해야 합니다. ADR 18개와 코드는 진화했는데 spec 만 디폴트라 누락이 누적되는 일을
 * CI 가 막아야 합니다.
 */
class OpenApiSpecE2eTest extends AbstractE2eTest {

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper om = new ObjectMapper();

    @Test
    void openapi_spec_은_info_와_security_scheme_을_포함() throws Exception {
        JsonNode spec = fetchSpec();

        // info
        assertThat(spec.path("info").path("title").asText()).isEqualTo("auth-service");
        assertThat(spec.path("info").path("version").asText()).isEqualTo("0.1.0");
        assertThat(spec.path("info").path("description").asText())
                .as("OPA / RFC 7662/7009 같은 핵심 키워드가 description 에 노출되어야 함")
                .contains("OPA")
                .contains("RFC 7662");

        // security schemes — bearerAuth + clientBasic 양쪽
        JsonNode schemes = spec.path("components").path("securitySchemes");
        assertThat(schemes.has("bearerAuth")).as("bearerAuth scheme").isTrue();
        assertThat(schemes.path("bearerAuth").path("type").asText()).isEqualTo("http");
        assertThat(schemes.path("bearerAuth").path("scheme").asText()).isEqualTo("bearer");
        assertThat(schemes.path("bearerAuth").path("bearerFormat").asText()).isEqualTo("JWT");

        assertThat(schemes.has("clientBasic")).as("clientBasic scheme").isTrue();
        assertThat(schemes.path("clientBasic").path("scheme").asText()).isEqualTo("basic");
    }

    @Test
    void rfc_7662_introspect_endpoint_가_spec_에_정확히_노출() throws Exception {
        JsonNode spec = fetchSpec();
        JsonNode op = spec.path("paths").path("/oauth2/introspect").path("post");

        assertThat(op.isMissingNode())
                .as("/oauth2/introspect POST 가 spec 에 등록되어야 함")
                .isFalse();
        assertThat(op.path("summary").asText()).contains("RFC 7662");
        assertThat(op.path("tags")).anyMatch(n -> n.asText().equals("oauth2"));

        // form-urlencoded body 의 schema 가 IntrospectForm 으로 노출되어야 함
        JsonNode formContent = op.path("requestBody").path("content")
                .path("application/x-www-form-urlencoded");
        assertThat(formContent.isMissingNode()).as("form-urlencoded content 정의 누락").isFalse();

        // 보안: clientBasic 요구
        assertThat(op.path("security")).anyMatch(n -> n.has("clientBasic"));

        // 응답 — 200 / 401 모두
        JsonNode responses = op.path("responses");
        assertThat(responses.has("200")).as("200 응답").isTrue();
        assertThat(responses.has("401")).as("401 응답").isTrue();
    }

    @Test
    void rfc_7009_revoke_endpoint_가_spec_에_정확히_노출() throws Exception {
        JsonNode spec = fetchSpec();
        JsonNode op = spec.path("paths").path("/oauth2/revoke").path("post");

        assertThat(op.isMissingNode())
                .as("/oauth2/revoke POST 가 spec 에 등록되어야 함")
                .isFalse();
        assertThat(op.path("summary").asText()).contains("RFC 7009");
        assertThat(op.path("tags")).anyMatch(n -> n.asText().equals("oauth2"));

        // form-urlencoded body 의 schema 노출
        JsonNode formContent = op.path("requestBody").path("content")
                .path("application/x-www-form-urlencoded");
        assertThat(formContent.isMissingNode()).as("form-urlencoded content 정의 누락").isFalse();

        // 응답 — 200 / 401 / 403 (권한 거부) 모두
        JsonNode responses = op.path("responses");
        assertThat(responses.has("200")).as("200 응답").isTrue();
        assertThat(responses.has("401")).as("401 응답").isTrue();
        assertThat(responses.has("403")).as("403 응답 (token.revoke scope 미보유)").isTrue();
    }

    @Test
    void first_party_endpoint_들도_summary_와_tag_을_가진다() throws Exception {
        JsonNode spec = fetchSpec();

        // /api/v1/auth/login
        JsonNode login = spec.path("paths").path("/api/v1/auth/login").path("post");
        assertThat(login.isMissingNode()).as("/api/v1/auth/login").isFalse();
        assertThat(login.path("summary").asText()).contains("로그인");
        assertThat(login.path("tags")).anyMatch(n -> n.asText().equals("auth"));

        // /api/v1/me/sessions GET — bearerAuth 요구
        JsonNode sessions = spec.path("paths").path("/api/v1/me/sessions").path("get");
        assertThat(sessions.isMissingNode()).as("/api/v1/me/sessions").isFalse();
        assertThat(sessions.path("security")).anyMatch(n -> n.has("bearerAuth"));
        assertThat(sessions.path("tags")).anyMatch(n -> n.asText().equals("session"));

        // /api/v1/admin/users/{userId}/roles
        JsonNode adminRoles = spec.path("paths").path("/api/v1/admin/users/{userId}/roles").path("post");
        assertThat(adminRoles.isMissingNode()).as("/api/v1/admin assignRole").isFalse();
        assertThat(adminRoles.path("security")).anyMatch(n -> n.has("bearerAuth"));
        assertThat(adminRoles.path("tags")).anyMatch(n -> n.asText().equals("admin"));
    }

    private JsonNode fetchSpec() throws Exception {
        HttpResponse<String> res = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/v3/api-docs"))
                        .timeout(Duration.ofSeconds(30))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(res.statusCode())
                .as("/v3/api-docs 가 200 으로 응답해야 함 (springdoc.api-docs.enabled=true 필요)")
                .isEqualTo(200);
        return om.readTree(res.body());
    }
}
