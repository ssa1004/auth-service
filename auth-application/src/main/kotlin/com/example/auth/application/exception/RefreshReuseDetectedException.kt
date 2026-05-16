package com.example.auth.application.exception

/**
 * 이미 회전된 refresh token 이 다시 들어왔습니다. 호출 시점에 이미 사용자의 모든 세션이
 * revoke 된 상태입니다 — 사용자는 재로그인이 강제됩니다.
 */
class RefreshReuseDetectedException : AuthenticationException("refresh token reuse detected")
