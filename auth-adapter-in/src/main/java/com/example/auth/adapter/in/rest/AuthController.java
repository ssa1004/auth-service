package com.example.auth.adapter.in.rest;

import com.example.auth.adapter.in.security.ClientIpResolver;
import com.example.auth.application.exception.MfaRequiredException;
import com.example.auth.application.port.in.LoginUseCase;
import com.example.auth.application.port.in.RefreshTokenUseCase;
import com.example.auth.application.port.in.RegisterUserUseCase;
import com.example.auth.application.port.in.VerifyMfaUseCase;
import com.example.auth.application.security.AuthTokens;
import com.example.auth.domain.common.UserId;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "auth")
public class AuthController {

    private final RegisterUserUseCase registerUserUseCase;
    private final LoginUseCase loginUseCase;
    private final VerifyMfaUseCase verifyMfaUseCase;
    private final RefreshTokenUseCase refreshTokenUseCase;
    private final ClientIpResolver clientIpResolver;

    @Operation(
            summary = "회원가입",
            description = "tenant + email + password 로 사용자 생성. password 는 BCrypt cost=12 로 해시.")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "생성 성공 — userId 반환"),
            @ApiResponse(responseCode = "400", description = "validation 실패 (email 형식 / password 길이 12-128 등)"),
            @ApiResponse(responseCode = "409", description = "이미 등록된 email")
    })
    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest req) {
        UserId id = registerUserUseCase.register(new RegisterUserUseCase.Command(
                req.tenantSlug(), req.email(), req.password()));
        return ResponseEntity.status(HttpStatus.CREATED).body(new RegisterResponse(id.asString()));
    }

    @Operation(
            summary = "로그인",
            description = """
                    bad credentials / locked / not-found 모두 동일 응답으로 정보 누설 차단.
                    MFA 활성 사용자는 401 + X-Mfa-Required 헤더 + body 의 mfaToken 으로 응답
                    — 호출자는 mfaToken 을 /verify-mfa 에 전달.
                    """)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "성공 — access + refresh 발급"),
            @ApiResponse(responseCode = "401", description = "bad credentials 또는 MFA 필요 (헤더로 구분)"),
            @ApiResponse(responseCode = "429", description = "rate limit (login-rate-burst 초과)")
    })
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @Valid @RequestBody LoginRequest req,
            HttpServletRequest http) {
        try {
            AuthTokens tokens = loginUseCase.login(new LoginUseCase.Command(
                    req.tenantSlug(),
                    req.email(),
                    req.password(),
                    clientIpResolver.resolve(http),
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

    @Operation(
            summary = "MFA TOTP 검증",
            description = "/login 응답의 mfaToken 과 6자리 TOTP 코드로 본 인증을 완료. challenge 토큰은 1회 consume.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "성공 — access + refresh 발급"),
            @ApiResponse(responseCode = "400", description = "코드 불일치 / 만료된 challenge / 이미 consume 된 challenge")
    })
    @PostMapping("/verify-mfa")
    public ResponseEntity<TokenResponse> verifyMfa(
            @Valid @RequestBody VerifyMfaRequest req,
            HttpServletRequest http) {
        AuthTokens tokens = verifyMfaUseCase.verify(new VerifyMfaUseCase.Command(
                req.mfaToken(),
                req.code(),
                clientIpResolver.resolve(http),
                http.getHeader("User-Agent"),
                req.deviceLabel()));
        return ResponseEntity.ok(TokenResponse.from(tokens));
    }

    @Operation(
            summary = "Refresh token 회전",
            description = """
                    refresh rotation + reuse detection. 회전된 token 이 다시 들어오면 모든
                    세션을 강제 revoke. 같은 IP 의 mobile retry 보호용 grace window 5초
                    (auth.refresh-reuse-grace-period) 가 적용됩니다.
                    """)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "성공 — 새 access + 새 refresh 발급"),
            @ApiResponse(responseCode = "401", description = "유효하지 않거나 이미 회전된 token (reuse 감지 시 사용자의 모든 세션 revoke)")
    })
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @Valid @RequestBody RefreshRequest req,
            HttpServletRequest http) {
        AuthTokens tokens = refreshTokenUseCase.refresh(new RefreshTokenUseCase.Command(
                req.refreshToken(), clientIpResolver.resolve(http), http.getHeader("User-Agent")));
        return ResponseEntity.ok(TokenResponse.from(tokens));
    }
}
