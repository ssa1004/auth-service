package com.example.auth.adapter.in.rest;

import com.example.auth.application.exception.MfaRequiredException;
import com.example.auth.application.port.in.LoginUseCase;
import com.example.auth.application.port.in.RefreshTokenUseCase;
import com.example.auth.application.port.in.RegisterUserUseCase;
import com.example.auth.application.port.in.VerifyMfaUseCase;
import com.example.auth.application.security.AuthTokens;
import com.example.auth.domain.common.UserId;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 회원가입 / 로그인 / refresh / MFA 검증 REST endpoint.
 *
 * <p>Spring Authorization Server 의 표준 OAuth2 endpoint (`/oauth2/token`,
 * `/oauth2/jwks`) 와 별도로 운영하는 *first-party* 인증 흐름입니다.
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final RegisterUserUseCase registerUserUseCase;
    private final LoginUseCase loginUseCase;
    private final VerifyMfaUseCase verifyMfaUseCase;
    private final RefreshTokenUseCase refreshTokenUseCase;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest req) {
        UserId id = registerUserUseCase.register(new RegisterUserUseCase.Command(
                req.tenantSlug(), req.email(), req.password()));
        return ResponseEntity.status(HttpStatus.CREATED).body(new RegisterResponse(id.asString()));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @Valid @RequestBody LoginRequest req,
            HttpServletRequest http) {
        try {
            AuthTokens tokens = loginUseCase.login(new LoginUseCase.Command(
                    req.tenantSlug(),
                    req.email(),
                    req.password(),
                    clientIp(http),
                    http.getHeader("User-Agent"),
                    req.deviceLabel()));
            return ResponseEntity.ok(TokenResponse.from(tokens));
        } catch (MfaRequiredException ex) {
            // 401 + 별도 헤더 — 클라이언트는 mfa_token 으로 /verify-mfa 호출.
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header("X-Mfa-Required", "true")
                    .body(TokenResponse.mfaRequired(ex.mfaChallengeToken()));
        }
    }

    @PostMapping("/verify-mfa")
    public ResponseEntity<TokenResponse> verifyMfa(
            @Valid @RequestBody VerifyMfaRequest req,
            HttpServletRequest http) {
        AuthTokens tokens = verifyMfaUseCase.verify(new VerifyMfaUseCase.Command(
                req.mfaToken(),
                req.code(),
                clientIp(http),
                http.getHeader("User-Agent"),
                req.deviceLabel()));
        return ResponseEntity.ok(TokenResponse.from(tokens));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @Valid @RequestBody RefreshRequest req,
            HttpServletRequest http) {
        AuthTokens tokens = refreshTokenUseCase.refresh(new RefreshTokenUseCase.Command(
                req.refreshToken(), clientIp(http), http.getHeader("User-Agent")));
        return ResponseEntity.ok(TokenResponse.from(tokens));
    }

    private static String clientIp(HttpServletRequest http) {
        // 운영에서는 reverse proxy 의 X-Forwarded-For 가 있으나 본 단계에서는 단순 처리.
        String xff = http.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            int comma = xff.indexOf(',');
            return comma > 0 ? xff.substring(0, comma).trim() : xff.trim();
        }
        return http.getRemoteAddr();
    }
}
