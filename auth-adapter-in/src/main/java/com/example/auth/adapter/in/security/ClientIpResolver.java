package com.example.auth.adapter.in.security;

import com.example.auth.application.security.AuthProperties;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;

/**
 * X-Forwarded-For 위조 차단 — 호출 직전 hop 이 신뢰된 proxy 일 때만 헤더를 받아들입니다.
 *
 * <p>위협 모델: 모든 X-Forwarded-For 를 그대로 신뢰하면 다음과 같은 우회가 가능합니다.
 * <ul>
 *   <li>per-IP rate limit 우회 — 매 요청마다 fake IP 를 보내면 bucket 이 매번 새로 생성</li>
 *   <li>refresh reuse grace 우회 — 다른 IP 로 가장하면 grace 처리되지 않고 일괄 revoke</li>
 *   <li>audit pollution — 임의 IP 를 audit log 에 적재</li>
 * </ul>
 *
 * <p>운영에서는 reverse proxy (nginx, ALB, Envoy) 가 X-Forwarded-For 를 *덮어쓰므로* 직전
 * hop 만 신뢰하면 안전합니다. {@code auth.trusted-proxies} 에 LB 의 CIDR 을 등록.
 * 비어있으면 X-Forwarded-For 는 무시되고 항상 socket 의 RemoteAddr 를 사용합니다 (안전한 default).
 *
 * <p>{@code X-Real-IP} 는 nginx 컨벤션이지만 X-Forwarded-For 만큼 표준화되어 있지 않아
 * 본 resolver 는 X-Forwarded-For 만 처리합니다 (운영자가 둘 다 쓰면 nginx 단에서 통합 권장).
 */
@Component
public class ClientIpResolver {

    private final List<IpAddressMatcher> trustedProxyMatchers;

    public ClientIpResolver(AuthProperties properties) {
        this.trustedProxyMatchers = compile(properties.trustedProxies());
    }

    /**
     * 호출자의 신뢰 가능한 client IP 를 반환합니다.
     *
     * <p>알고리즘:
     * <ol>
     *   <li>{@code request.getRemoteAddr()} (직전 hop) 가 trustedProxies 에 들어있는가?</li>
     *   <li>그렇다면 X-Forwarded-For 의 *왼쪽 첫 번째* 항목을 client IP 로 채택.</li>
     *   <li>그렇지 않으면 X-Forwarded-For 는 위조 가능성이 있으므로 무시하고 RemoteAddr 사용.</li>
     * </ol>
     *
     * <p>X-Forwarded-For 는 RFC 7239 에 따라 {@code client, proxy1, proxy2} 형식으로 누적됩니다.
     * 본 resolver 는 가장 왼쪽 (= 원 client) 만 사용합니다.
     */
    public String resolve(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (!isTrustedProxy(remoteAddr)) {
            return remoteAddr;
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded == null || forwarded.isBlank()) {
            return remoteAddr;
        }
        int comma = forwarded.indexOf(',');
        String first = comma > 0 ? forwarded.substring(0, comma).trim() : forwarded.trim();
        return first.isEmpty() ? remoteAddr : first;
    }

    private boolean isTrustedProxy(String address) {
        if (address == null || address.isBlank()) return false;
        for (IpAddressMatcher matcher : trustedProxyMatchers) {
            if (matcher.matches(address)) return true;
        }
        return false;
    }

    private static List<IpAddressMatcher> compile(List<String> cidrs) {
        if (cidrs == null || cidrs.isEmpty()) return List.of();
        List<IpAddressMatcher> matchers = new ArrayList<>(cidrs.size());
        for (String cidr : cidrs) {
            if (cidr == null || cidr.isBlank()) continue;
            matchers.add(new IpAddressMatcher(cidr.trim()));
        }
        return List.copyOf(matchers);
    }
}
