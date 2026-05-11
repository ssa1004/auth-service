package com.example.auth.bootstrap;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.adapter.out.security.JwkSourceProvider;
import com.example.auth.application.port.in.LoginUseCase;
import com.example.auth.application.port.in.RefreshTokenUseCase;
import com.example.auth.application.port.in.RegisterUserUseCase;
import com.example.auth.application.port.in.VerifyMfaUseCase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.example.auth.application.port.out.RateLimiter;

/**
 * Spring 컨텍스트가 정상적으로 부팅되는지 확인. 외부 Redis / Postgres 가 없어도 통과.
 *
 * <p>RateLimiter 만 mock — 실제 RedisRateLimiterAdapter 는 부팅 시 Lettuce 가 RedisClient
 * 를 만들어 두기만 하므로 connect 는 일어나지 않지만, mock 으로 명시 / 안전 가드.
 */
@SpringBootTest(classes = AuthServiceApplication.class)
@ActiveProfiles("test")
class ApplicationContextSmokeTest {

    @MockitoBean
    RateLimiter rateLimiter;

    @Autowired
    ApplicationContext context;

    @Autowired
    JwkSourceProvider jwkSourceProvider;

    @Test
    void 컨텍스트가_부팅되고_핵심_use_case_빈이_등록된다() {
        assertThat(context.getBean(RegisterUserUseCase.class)).isNotNull();
        assertThat(context.getBean(LoginUseCase.class)).isNotNull();
        assertThat(context.getBean(VerifyMfaUseCase.class)).isNotNull();
        assertThat(context.getBean(RefreshTokenUseCase.class)).isNotNull();
    }

    @Test
    void 부팅_시_초기_JWK_가_생성되어_있다() {
        assertThat(jwkSourceProvider.current()).isNotNull();
        assertThat(jwkSourceProvider.jwkSet().size()).isEqualTo(1);
    }
}
