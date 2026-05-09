package com.example.auth.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.application.port.out.MfaSecretCipher;
import com.example.auth.application.port.out.MfaSecretRepository;
import com.example.auth.application.port.out.TenantRepository;
import com.example.auth.application.port.out.TotpVerifier;
import com.example.auth.application.port.out.UserRepository;
import com.example.auth.domain.mfa.MfaMethod;
import com.example.auth.domain.mfa.MfaSecret;
import com.example.auth.domain.tenant.Tenant;
import com.example.auth.domain.user.User;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * MFA 흐름 e2e — 비밀번호 통과 → 401 + mfa_token → /verify-mfa 로 access 발급.
 *
 * <p>잘못된 코드는 InvalidCredentials. challenge 토큰은 1회 consume.
 */
class MfaFlowE2eTest extends AbstractE2eTest {

    @Autowired UserRepository userRepository;
    @Autowired TenantRepository tenantRepository;
    @Autowired MfaSecretRepository mfaSecretRepository;
    @Autowired MfaSecretCipher mfaSecretCipher;
    @Autowired TotpVerifier totpVerifier;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void mfa_활성_사용자는_login_시_mfa_required_그_후_verify_로_access_발급() throws Exception {
        // 1) seed: tenant + user with MFA enabled
        Tenant tenant = tenantRepository.findBySlug("acme")
                .orElseGet(() -> tenantRepository.save(Tenant.create("acme", "ACME", Instant.now())));
        String email = "mfa-" + System.nanoTime() + "@example.com";
        String hash = new BCryptPasswordEncoder(4).encode("longenoughpw1234");
        User u = userRepository.save(User.register(tenant.id(), email, hash, Instant.now())
                .markVerified(Instant.now())
                .enableMfa(Instant.now()));
        String secret = totpVerifier.generateSecret();
        mfaSecretRepository.save(MfaSecret.enroll(u.id(), mfaSecretCipher.encrypt(secret),
                MfaMethod.TOTP, Instant.now()).confirm(Instant.now()));

        // 2) login → 401 + mfa_token
        HttpResponse<String> login = post("/api/v1/auth/login", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234","deviceLabel":"e2e"}
                """.formatted(email));
        assertThat(login.statusCode()).isEqualTo(401);
        assertThat(login.headers().firstValue("X-Mfa-Required")).contains("true");
        String mfaToken = json(login.body(), "mfaToken");
        assertThat(mfaToken).isNotBlank();

        // 3) 잘못된 코드 → 401
        HttpResponse<String> wrong = post("/api/v1/auth/verify-mfa", """
                {"mfaToken":"%s","code":"000000","deviceLabel":"e2e"}
                """.formatted(mfaToken));
        assertThat(wrong.statusCode()).isEqualTo(401);

        // 4) 새 challenge 발급 (이전은 consume 되어 사라짐) — 다시 login 호출.
        HttpResponse<String> login2 = post("/api/v1/auth/login", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234","deviceLabel":"e2e"}
                """.formatted(email));
        String freshMfaToken = json(login2.body(), "mfaToken");

        // 5) 올바른 TOTP 생성 + verify
        var gen = new DefaultCodeGenerator();
        long bucket = new SystemTimeProvider().getTime() / 30;
        String code = gen.generate(secret, bucket);
        HttpResponse<String> ok = post("/api/v1/auth/verify-mfa", """
                {"mfaToken":"%s","code":"%s","deviceLabel":"e2e"}
                """.formatted(freshMfaToken, code));
        assertThat(ok.statusCode()).isEqualTo(200);
        assertThat(json(ok.body(), "accessToken")).startsWith("ey");
    }

    @Test
    void mfa_challenge_replay_차단_같은_token_으로_2번_verify_불가() throws Exception {
        Tenant tenant = tenantRepository.findBySlug("acme")
                .orElseGet(() -> tenantRepository.save(Tenant.create("acme", "ACME", Instant.now())));
        String email = "mfa-replay-" + System.nanoTime() + "@example.com";
        String hash = new BCryptPasswordEncoder(4).encode("longenoughpw1234");
        User u = userRepository.save(User.register(tenant.id(), email, hash, Instant.now())
                .markVerified(Instant.now())
                .enableMfa(Instant.now()));
        String secret = totpVerifier.generateSecret();
        mfaSecretRepository.save(MfaSecret.enroll(u.id(), mfaSecretCipher.encrypt(secret),
                MfaMethod.TOTP, Instant.now()).confirm(Instant.now()));

        HttpResponse<String> login = post("/api/v1/auth/login", """
                {"tenantSlug":"acme","email":"%s","password":"longenoughpw1234","deviceLabel":"e2e"}
                """.formatted(email));
        String mfaToken = json(login.body(), "mfaToken");

        var gen = new DefaultCodeGenerator();
        long bucket = new SystemTimeProvider().getTime() / 30;
        String code = gen.generate(secret, bucket);

        HttpResponse<String> first = post("/api/v1/auth/verify-mfa", """
                {"mfaToken":"%s","code":"%s","deviceLabel":"e2e"}
                """.formatted(mfaToken, code));
        assertThat(first.statusCode()).isEqualTo(200);

        // 같은 mfaToken 으로 다시 → consume 되어 401
        HttpResponse<String> second = post("/api/v1/auth/verify-mfa", """
                {"mfaToken":"%s","code":"%s","deviceLabel":"e2e"}
                """.formatted(mfaToken, code));
        assertThat(second.statusCode()).isEqualTo(401);
    }

    private HttpResponse<String> post(String path, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(baseUrl() + path))
                        .timeout(java.time.Duration.ofSeconds(30))
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
        if (end < 0) return null;
        return body.substring(start, end);
    }
}
