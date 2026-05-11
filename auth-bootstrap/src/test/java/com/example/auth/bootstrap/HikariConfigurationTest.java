package com.example.auth.bootstrap;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.application.port.out.RateLimiter;
import com.zaxxer.hikari.HikariDataSource;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * HikariCP 운영 튜닝 (ADR-0009) 이 application.yml 에서 정상 binding 되는지 확인.
 *
 * <p>test profile 은 leak detection / 풀 사이즈를 별도 값으로 override 하므로,
 * 본 테스트는 *prod* 값이 application.yml 에 살아 있는지를 보기 위해 prop 을 명시 주입.
 */
@SpringBootTest(classes = AuthServiceApplication.class)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "spring.datasource.hikari.maximum-pool-size=18",
        "spring.datasource.hikari.minimum-idle=4",
        "spring.datasource.hikari.connection-timeout=3000",
        "spring.datasource.hikari.max-lifetime=1740000",
        "spring.datasource.hikari.idle-timeout=600000",
        "spring.datasource.hikari.leak-detection-threshold=30000",
        "spring.datasource.hikari.pool-name=AuthHikariPool",
})
class HikariConfigurationTest {

    @MockitoBean
    RateLimiter rateLimiter;

    @Autowired
    DataSource dataSource;

    @Test
    void HikariDataSource_가_명시_튜닝_값으로_바인딩된다() {
        assertThat(dataSource).isInstanceOf(HikariDataSource.class);
        HikariDataSource ds = (HikariDataSource) dataSource;

        assertThat(ds.getMaximumPoolSize()).isEqualTo(18);
        assertThat(ds.getMinimumIdle()).isEqualTo(4);
        assertThat(ds.getConnectionTimeout()).isEqualTo(3000L);
        assertThat(ds.getMaxLifetime()).isEqualTo(1_740_000L);
        assertThat(ds.getIdleTimeout()).isEqualTo(600_000L);
        assertThat(ds.getLeakDetectionThreshold()).isEqualTo(30_000L);
        assertThat(ds.getPoolName()).isEqualTo("AuthHikariPool");
    }
}
