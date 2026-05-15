package com.example.auth.domain.common

/**
 * 로그 / audit 출력 시 이메일 PII 를 마스킹합니다.
 *
 * 평문 비밀번호 / TOTP secret / refresh token 은 *어떤 경우에도* 로그에 등장하면 안 됩니다.
 * 이메일은 audit 추적 가치가 있어 마스킹된 형태로만 노출합니다.
 *
 * ```
 *   alice@example.com → a***e@e***e.com
 *   ab@x.io          → a***b@x***x.io
 *   a@b.c            → a***@b***.c
 * ```
 */
object EmailMasker {

    @JvmStatic
    fun mask(email: String?): String {
        if (email == null || email.isBlank()) {
            return "(blank)"
        }
        val at = email.indexOf('@')
        if (at <= 0 || at == email.length - 1) {
            return "***"
        }
        val local = email.substring(0, at)
        val domain = email.substring(at + 1)
        val dot = domain.lastIndexOf('.')
        if (dot <= 0) {
            return maskPart(local) + "@***"
        }
        val domainName = domain.substring(0, dot)
        val tld = domain.substring(dot)
        return maskPart(local) + "@" + maskPart(domainName) + tld
    }

    private fun maskPart(part: String): String {
        if (part.length <= 1) {
            return part + "***"
        }
        return "" + part[0] + "***" + part[part.length - 1]
    }
}
