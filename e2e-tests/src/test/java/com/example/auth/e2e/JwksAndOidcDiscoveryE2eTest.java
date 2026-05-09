package com.example.auth.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;

/**
 * Spring Authorization Server 가 자동으로 노출하는 표준 endpoint 가 살아있는지 확인.
 */
class JwksAndOidcDiscoveryE2eTest extends AbstractE2eTest {

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void jwks_endpoint_가_현재_키를_반환() throws Exception {
        HttpResponse<String> res = http.send(HttpRequest.newBuilder(
                        URI.create(baseUrl() + "/oauth2/jwks")).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(res.statusCode()).isEqualTo(200);
        // RSA 키 1개 이상 노출, public 컴포넌트 (n, e) 만.
        assertThat(res.body()).contains("\"kty\":\"RSA\"");
        assertThat(res.body()).contains("\"use\":\"sig\"");
        // private 컴포넌트는 절대 노출되지 않아야 함.
        assertThat(res.body()).doesNotContain("\"d\":");
        assertThat(res.body()).doesNotContain("\"p\":");
        assertThat(res.body()).doesNotContain("\"q\":");
    }

    @Test
    void oidc_discovery_endpoint_가_표준_metadata_를_반환() throws Exception {
        HttpResponse<String> res = http.send(HttpRequest.newBuilder(
                        URI.create(baseUrl() + "/.well-known/openid-configuration")).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(res.statusCode()).isEqualTo(200);
        assertThat(res.body()).contains("\"issuer\"");
        assertThat(res.body()).contains("\"jwks_uri\"");
        assertThat(res.body()).contains("\"token_endpoint\"");
    }
}
