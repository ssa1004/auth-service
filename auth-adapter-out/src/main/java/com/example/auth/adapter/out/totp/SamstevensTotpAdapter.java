package com.example.auth.adapter.out.totp;

import com.example.auth.application.port.out.TotpVerifier;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.stereotype.Component;

/**
 * RFC 6238 TOTP — dev.samstevens.totp 라이브러리. SHA1 / 30s / 6 digits
 * (Google Authenticator 호환). window = ±1 step (=30초 시계 어긋남 허용).
 */
@Component
public class SamstevensTotpAdapter implements TotpVerifier {

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator(32);
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
    private final CodeVerifier verifier;

    public SamstevensTotpAdapter() {
        DefaultCodeVerifier v = new DefaultCodeVerifier(codeGenerator, timeProvider);
        v.setTimePeriod(30);
        v.setAllowedTimePeriodDiscrepancy(1);
        this.verifier = v;
    }

    @Override
    public String generateSecret() {
        return secretGenerator.generate();
    }

    @Override
    public String otpAuthUrl(String label, String issuer, String secret) {
        return "otpauth://totp/" + urlEncode(issuer) + ":" + urlEncode(label)
                + "?secret=" + secret + "&issuer=" + urlEncode(issuer);
    }

    @Override
    public boolean verify(String secret, String code) {
        return verifier.isValidCode(secret, code);
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }
}
