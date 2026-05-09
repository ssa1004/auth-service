package com.example.auth.domain.common;

/**
 * 로그 / audit 출력 시 이메일 PII 를 마스킹합니다.
 * <p>
 * 평문 비밀번호 / TOTP secret / refresh token 은 *어떤 경우에도* 로그에 등장하면 안 됩니다.
 * 이메일은 audit 추적 가치가 있어 마스킹된 형태로만 노출합니다.
 *
 * <pre>
 *   alice@example.com → a***e@e***e.com
 *   ab@x.io          → a***b@x***x.io
 *   a@b.c            → a***@b***.c
 * </pre>
 */
public final class EmailMasker {

    private EmailMasker() {
    }

    public static String mask(String email) {
        if (email == null || email.isBlank()) {
            return "(blank)";
        }
        int at = email.indexOf('@');
        if (at <= 0 || at == email.length() - 1) {
            return "***";
        }
        String local = email.substring(0, at);
        String domain = email.substring(at + 1);
        int dot = domain.lastIndexOf('.');
        if (dot <= 0) {
            return maskPart(local) + "@***";
        }
        String domainName = domain.substring(0, dot);
        String tld = domain.substring(dot);
        return maskPart(local) + "@" + maskPart(domainName) + tld;
    }

    private static String maskPart(String part) {
        if (part.length() <= 1) {
            return part + "***";
        }
        return part.charAt(0) + "***" + part.charAt(part.length() - 1);
    }
}
