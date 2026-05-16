package com.example.auth.application.exception

/**
 * 비밀번호 검증은 통과했지만 MFA 가 활성 사용자라 추가 단계 필요.
 * 응답에는 `mfaToken` (challenge id) 만 노출 — access token 은 발급되지 않음.
 */
class MfaRequiredException(private val mfaChallengeToken: String) : RuntimeException("mfa required") {

    fun mfaChallengeToken(): String = mfaChallengeToken
}
