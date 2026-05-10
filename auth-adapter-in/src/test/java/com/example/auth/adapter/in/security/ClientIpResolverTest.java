package com.example.auth.adapter.in.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.application.security.AuthProperties;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * X-Forwarded-For 위조 차단의 회귀 락다운.
 *
 * <p>위협: 모든 X-Forwarded-For 를 무조건 신뢰하면 매 요청마다 fake IP 를 보내 per-IP rate
 * limit / refresh reuse grace 를 우회할 수 있습니다. trusted proxy 가 직전 hop 일 때만
 * 헤더를 수용해야 합니다.
 */
class ClientIpResolverTest {

    @Test
    void trustedProxies_가_비어있으면_X_Forwarded_For_는_무시되고_RemoteAddr_사용() {
        ClientIpResolver resolver = new ClientIpResolver(propertiesWithTrusted(List.of()));
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("203.0.113.10");
        req.addHeader("X-Forwarded-For", "9.9.9.9");

        assertThat(resolver.resolve(req)).isEqualTo("203.0.113.10");
    }

    @Test
    void 직전_hop_이_trusted_가_아니면_X_Forwarded_For_무시() {
        // trustedProxies 에 LB 만 있고, 호출자가 LB 를 거치지 않은 경우 (직접 호출).
        ClientIpResolver resolver = new ClientIpResolver(propertiesWithTrusted(List.of("10.0.0.0/8")));
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("203.0.113.10"); // 외부에서 직접 친 척
        req.addHeader("X-Forwarded-For", "9.9.9.9"); // 위조 시도

        assertThat(resolver.resolve(req)).isEqualTo("203.0.113.10");
    }

    @Test
    void 직전_hop_이_trusted_이면_X_Forwarded_For_의_왼쪽_첫_항목_채택() {
        ClientIpResolver resolver = new ClientIpResolver(propertiesWithTrusted(List.of("10.0.0.0/8")));
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.5"); // LB 가 직전 hop
        req.addHeader("X-Forwarded-For", "203.0.113.10, 10.0.0.5");

        assertThat(resolver.resolve(req)).isEqualTo("203.0.113.10");
    }

    @Test
    void 직전_hop_이_trusted_여도_X_Forwarded_For_가_없으면_RemoteAddr_사용() {
        ClientIpResolver resolver = new ClientIpResolver(propertiesWithTrusted(List.of("10.0.0.0/8")));
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.5");

        assertThat(resolver.resolve(req)).isEqualTo("10.0.0.5");
    }

    @Test
    void 직전_hop_이_loopback_trusted_여도_X_Forwarded_For_빈_헤더는_무시() {
        ClientIpResolver resolver = new ClientIpResolver(propertiesWithTrusted(List.of("127.0.0.1/32")));
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("127.0.0.1");
        req.addHeader("X-Forwarded-For", "   ");

        assertThat(resolver.resolve(req)).isEqualTo("127.0.0.1");
    }

    @Test
    void 여러_CIDR_중_하나라도_매칭되면_trusted() {
        ClientIpResolver resolver = new ClientIpResolver(propertiesWithTrusted(
                List.of("10.0.0.0/8", "172.16.0.0/12")));
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("172.20.5.1");
        req.addHeader("X-Forwarded-For", "203.0.113.99");

        assertThat(resolver.resolve(req)).isEqualTo("203.0.113.99");
    }

    @Test
    void IPv6_loopback_도_정상_처리() {
        ClientIpResolver resolver = new ClientIpResolver(propertiesWithTrusted(List.of("::1/128")));
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("0:0:0:0:0:0:0:1");
        req.addHeader("X-Forwarded-For", "203.0.113.7");

        assertThat(resolver.resolve(req)).isEqualTo("203.0.113.7");
    }

    @Test
    void X_Forwarded_For_의_단일_항목도_정상_파싱() {
        ClientIpResolver resolver = new ClientIpResolver(propertiesWithTrusted(List.of("10.0.0.0/8")));
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.5");
        req.addHeader("X-Forwarded-For", "198.51.100.7");

        assertThat(resolver.resolve(req)).isEqualTo("198.51.100.7");
    }

    @Test
    void blank_및_null_CIDR_은_무시되어_NPE_없이_부팅() {
        // 운영자가 yml 에 빈 항목을 섞어둬도 부팅이 깨지지 않아야 함.
        ClientIpResolver resolver = new ClientIpResolver(propertiesWithTrusted(
                java.util.Arrays.asList("10.0.0.0/8", "", "  ", null)));
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.5");
        req.addHeader("X-Forwarded-For", "203.0.113.1");

        assertThat(resolver.resolve(req)).isEqualTo("203.0.113.1");
    }

    private static AuthProperties propertiesWithTrusted(List<String> cidrs) {
        AuthProperties d = AuthProperties.defaults();
        return new AuthProperties(
                d.accessTokenTtl(), d.refreshTokenTtl(), d.refreshReuseGracePeriod(),
                d.bcryptCost(), d.loginRateBurst(), d.loginRateWindow(),
                d.jwtIssuer(), d.mfaIssuer(), cidrs, d.opa());
    }
}
