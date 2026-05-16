package com.example.auth.application.exception

/**
 * 인증 실패의 부모. 사용자에게 노출되는 메시지는 *항상 동일* — bad credentials / user not
 * found / locked 모두 같은 응답으로 내보냅니다 (정보 누설 방지).
 *
 * 세부 사유는 audit log 에만 기록.
 */
open class AuthenticationException(message: String) : RuntimeException(message)
