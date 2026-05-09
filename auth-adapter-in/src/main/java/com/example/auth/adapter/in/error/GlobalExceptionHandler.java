package com.example.auth.adapter.in.error;

import com.example.auth.application.exception.AuthenticationException;
import com.example.auth.application.exception.PolicyDeniedException;
import com.example.auth.application.exception.RateLimitedException;
import com.example.auth.application.exception.RefreshReuseDetectedException;
import com.example.auth.application.exception.TenantNotFoundException;
import com.example.auth.application.exception.UserAlreadyExistsException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 모든 예외 응답은 *동일한 모양* — 클라이언트가 status code + code 만으로 분기.
 * 메시지는 영어 한 줄, PII / 비밀 누설 금지.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(RefreshReuseDetectedException.class)
    public ResponseEntity<ApiError> reuse(RefreshReuseDetectedException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiError("refresh_reuse_detected", ex.getMessage()));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiError> auth(AuthenticationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiError("invalid_credentials", ex.getMessage()));
    }

    @ExceptionHandler(PolicyDeniedException.class)
    public ResponseEntity<ApiError> policy(PolicyDeniedException ex) {
        // RBAC 통과 후 ABAC 정책에서 막힘 — 인증은 됐고 권한이 부족한 상태이므로 403.
        // reasons 는 message 안에 join 되어 들어가 있음 (PII 미포함이 정책 작성 규칙).
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ApiError("policy_denied", ex.getMessage()));
    }

    @ExceptionHandler(RateLimitedException.class)
    public ResponseEntity<ApiError> rate(RateLimitedException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(new ApiError("rate_limited", ex.getMessage()));
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiError> already(UserAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ApiError("conflict", ex.getMessage()));
    }

    @ExceptionHandler(TenantNotFoundException.class)
    public ResponseEntity<ApiError> tenantNotFound(TenantNotFoundException ex) {
        // 보안 관점: 존재하지 않는 tenant slug 를 노출해도 큰 정보 누설은 아니지만, 401
        // 으로 통일해도 무방. 본 단계는 명확성 위해 404 로.
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiError("tenant_not_found", "tenant not found"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> validation(MethodArgumentNotValidException ex) {
        // validation 메시지에 password 평문이 들어가지 않도록 — body 를 가리지 않고 message
        // 만 노출하는 정책. (jakarta.validation 은 기본적으로 invalid value 를 메시지에
        // 포함하지 않음)
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiError("invalid_request", ex.getBindingResult().getAllErrors().size()
                        + " validation error(s)"));
    }

    public record ApiError(String code, String message) {
    }
}
