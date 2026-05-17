package com.example.auth.adapter.`in`.error

import com.example.auth.application.exception.AuthenticationException
import com.example.auth.application.exception.PolicyDeniedException
import com.example.auth.application.exception.RateLimitedException
import com.example.auth.application.exception.RefreshReuseDetectedException
import com.example.auth.application.exception.TenantNotFoundException
import com.example.auth.application.exception.UserAlreadyExistsException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

/**
 * 모든 예외 응답은 *동일한 모양* — 클라이언트가 status code + code 만으로 분기.
 * 메시지는 영어 한 줄, PII / 비밀 누설 금지.
 */
@RestControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(RefreshReuseDetectedException::class)
    fun reuse(ex: RefreshReuseDetectedException): ResponseEntity<ApiError> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(ApiError("refresh_reuse_detected", ex.message))

    @ExceptionHandler(AuthenticationException::class)
    fun auth(ex: AuthenticationException): ResponseEntity<ApiError> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(ApiError("invalid_credentials", ex.message))

    @ExceptionHandler(PolicyDeniedException::class)
    fun policy(ex: PolicyDeniedException): ResponseEntity<ApiError> =
        // RBAC 통과 후 ABAC 정책에서 막힘 — 인증은 됐고 권한이 부족한 상태이므로 403.
        // reasons 는 message 안에 join 되어 들어가 있음 (PII 미포함이 정책 작성 규칙).
        ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(ApiError("policy_denied", ex.message))

    @ExceptionHandler(RateLimitedException::class)
    fun rate(ex: RateLimitedException): ResponseEntity<ApiError> =
        ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
            .body(ApiError("rate_limited", ex.message))

    @ExceptionHandler(UserAlreadyExistsException::class)
    fun already(ex: UserAlreadyExistsException): ResponseEntity<ApiError> =
        ResponseEntity.status(HttpStatus.CONFLICT)
            .body(ApiError("conflict", ex.message))

    @ExceptionHandler(TenantNotFoundException::class)
    fun tenantNotFound(ex: TenantNotFoundException): ResponseEntity<ApiError> =
        // 보안 관점: 존재하지 않는 tenant slug 를 노출해도 큰 정보 누설은 아니지만, 401
        // 으로 통일해도 무방. 본 단계는 명확성 위해 404 로.
        ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(ApiError("tenant_not_found", "tenant not found"))

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun validation(ex: MethodArgumentNotValidException): ResponseEntity<ApiError> =
        // validation 메시지에 password 평문이 들어가지 않도록 — body 를 가리지 않고 message
        // 만 노출하는 정책. (jakarta.validation 은 기본적으로 invalid value 를 메시지에
        // 포함하지 않음)
        ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(ApiError("invalid_request", "${ex.bindingResult.allErrors.size} validation error(s)"))

    @JvmRecord
    data class ApiError(val code: String, val message: String?)
}
