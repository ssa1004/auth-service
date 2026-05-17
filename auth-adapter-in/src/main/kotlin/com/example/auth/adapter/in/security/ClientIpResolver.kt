package com.example.auth.adapter.`in`.security

import com.example.auth.application.security.AuthProperties
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.web.util.matcher.IpAddressMatcher
import org.springframework.stereotype.Component

/**
 * X-Forwarded-For 위조 차단 — 호출 직전 hop 이 신뢰된 proxy 일 때만 헤더를 받아들입니다.
 *
 * 위협 모델: 모든 X-Forwarded-For 를 그대로 신뢰하면 다음과 같은 우회가 가능합니다.
 * - per-IP rate limit 우회 — 매 요청마다 fake IP 를 보내면 bucket 이 매번 새로 생성
 * - refresh reuse grace 우회 — 다른 IP 로 가장하면 grace 처리되지 않고 일괄 revoke
 * - audit pollution — 임의 IP 를 audit log 에 적재
 *
 * 운영에서는 reverse proxy (nginx, ALB, Envoy) 가 X-Forwarded-For 를 *덮어쓰므로* 직전
 * hop 만 신뢰하면 안전합니다. `auth.trusted-proxies` 에 LB 의 CIDR 을 등록.
 * 비어있으면 X-Forwarded-For 는 무시되고 항상 socket 의 RemoteAddr 를 사용합니다 (안전한 default).
 *
 * `X-Real-IP` 는 nginx 컨벤션이지만 X-Forwarded-For 만큼 표준화되어 있지 않아
 * 본 resolver 는 X-Forwarded-For 만 처리합니다 (운영자가 둘 다 쓰면 nginx 단에서 통합 권장).
 */
@Component
class ClientIpResolver(properties: AuthProperties) {

    private val trustedProxyMatchers: List<IpAddressMatcher> = compile(properties.trustedProxies)

    /**
     * 호출자의 신뢰 가능한 client IP 를 반환합니다.
     *
     * 알고리즘:
     * 1. `request.remoteAddr` (직전 hop) 가 trustedProxies 에 들어있는가?
     * 2. 그렇다면 X-Forwarded-For 의 *왼쪽 첫 번째* 항목을 client IP 로 채택.
     * 3. 그렇지 않으면 X-Forwarded-For 는 위조 가능성이 있으므로 무시하고 RemoteAddr 사용.
     *
     * X-Forwarded-For 는 RFC 7239 에 따라 `client, proxy1, proxy2` 형식으로 누적됩니다.
     * 본 resolver 는 가장 왼쪽 (= 원 client) 만 사용합니다.
     */
    fun resolve(request: HttpServletRequest): String {
        val remoteAddr = request.remoteAddr
        if (!isTrustedProxy(remoteAddr)) {
            return remoteAddr
        }
        val forwarded = request.getHeader("X-Forwarded-For")
        if (forwarded.isNullOrBlank()) {
            return remoteAddr
        }
        val comma = forwarded.indexOf(',')
        val first = if (comma > 0) forwarded.substring(0, comma).trim() else forwarded.trim()
        return first.ifEmpty { remoteAddr }
    }

    private fun isTrustedProxy(address: String?): Boolean {
        if (address.isNullOrBlank()) return false
        for (matcher in trustedProxyMatchers) {
            if (matcher.matches(address)) return true
        }
        return false
    }

    private companion object {
        fun compile(cidrs: List<String>?): List<IpAddressMatcher> {
            if (cidrs.isNullOrEmpty()) return emptyList()
            val matchers = ArrayList<IpAddressMatcher>(cidrs.size)
            for (cidr in cidrs) {
                if (cidr.isNullOrBlank()) continue
                matchers.add(IpAddressMatcher(cidr.trim()))
            }
            return java.util.List.copyOf(matchers)
        }
    }
}
