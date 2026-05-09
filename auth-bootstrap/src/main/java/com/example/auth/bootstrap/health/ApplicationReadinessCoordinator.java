package com.example.auth.bootstrap.health;

import com.example.auth.adapter.out.security.JwkSourceProvider;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthContributor;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.availability.ApplicationAvailability;
import org.springframework.boot.availability.AvailabilityChangeEvent;
import org.springframework.boot.availability.LivenessState;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * K8s readiness 의 단일 게이트 (ADR-0010).
 *
 * <p>Spring Boot 가 기본으로 제공하는 readinessState 는 "AvailabilityChangeEvent 를
 * 받았는가" 만 본다. 이 코디네이터는 *주기적으로* DB / Redis health indicator 를 깨워
 * REFUSING_TRAFFIC 또는 ACCEPTING_TRAFFIC 로 토글한다.
 *
 * <p>JWK 초기 키 미생성 시 {@link #onReady} 에서 startup fail — readiness=DOWN 만으로는
 * fail-fast 가 안 되므로 명시적으로 예외를 던져 컨테이너 재시작을 유도.
 *
 * <p>외부 의존 health 가 잠깐 흔들릴 때마다 readiness 를 토글하면 노이즈가 크므로
 * "연속 N회 실패" 를 본다 (회로차단기처럼). N 은 작게 시작 (3회).
 */
@Component
public class ApplicationReadinessCoordinator {

    private static final int CONSECUTIVE_FAILURE_THRESHOLD = 3;

    private final ApplicationAvailability availability;
    private final ApplicationEventPublisher publisher;
    private final HealthContributorRegistry healthRegistry;
    private final JwkSourceProvider jwkSourceProvider;

    private int consecutiveFailures = 0;

    public ApplicationReadinessCoordinator(ApplicationAvailability availability,
                                           ApplicationEventPublisher publisher,
                                           HealthContributorRegistry healthRegistry,
                                           JwkSourceProvider jwkSourceProvider) {
        this.availability = availability;
        this.publisher = publisher;
        this.healthRegistry = healthRegistry;
        this.jwkSourceProvider = jwkSourceProvider;
    }

    /**
     * 부팅 직후 한 번 실행 — JWK 초기 키 미생성 시 fail-fast.
     *
     * <p>JwkConfig 에서 RSA 키를 만들지만, KMS 도입 후 KMS 가 응답 못 하는 케이스에서
     * 빈 provider 가 들어올 수 있다. 그럴 때 readiness=DOWN 으로만 두면 K8s 가 영원히
     * 트래픽을 안 보내기만 할 뿐 재시작은 안 함 → 명시적 예외로 컨테이너 재기동 유도.
     */
    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        if (jwkSourceProvider.jwkSet().getKeys().isEmpty()) {
            // ApplicationReadyEvent 리스너에서 예외를 던지면 Spring 이 종료 코드 1 로
            // 빠짐 → K8s 가 컨테이너 재시작.
            throw new IllegalStateException("JWK 초기 키 미생성 — KMS / 키 소스 점검 필요");
        }
        // 부팅 직후 ACCEPTING_TRAFFIC 으로 명시 (Spring 기본도 같지만 명시).
        AvailabilityChangeEvent.publish(publisher, this, ReadinessState.ACCEPTING_TRAFFIC);
        AvailabilityChangeEvent.publish(publisher, this, LivenessState.CORRECT);
    }

    /**
     * 5초마다 외부 의존 상태 확인. 연속 3회 실패면 readiness=REFUSING_TRAFFIC 로 토글.
     *
     * <p>주기는 K8s readinessProbe.periodSeconds (10s) 보다 짧게 — 그래야 K8s 가
     * 다음 probe 호출 시점에 최신 상태를 본다.
     */
    @Scheduled(fixedDelay = 5000L)
    public void recheckExternalDependencies() {
        boolean dbUp = isContributorUp("db");
        boolean redisUp = isContributorUp("redis");

        if (dbUp && redisUp) {
            if (consecutiveFailures > 0) {
                consecutiveFailures = 0;
                AvailabilityChangeEvent.publish(publisher, this, ReadinessState.ACCEPTING_TRAFFIC);
            }
            return;
        }

        consecutiveFailures++;
        if (consecutiveFailures >= CONSECUTIVE_FAILURE_THRESHOLD
                && availability.getReadinessState() == ReadinessState.ACCEPTING_TRAFFIC) {
            AvailabilityChangeEvent.publish(publisher, this, ReadinessState.REFUSING_TRAFFIC);
        }
    }

    /**
     * registry 에서 이름으로 contributor 조회 후 상태를 본다.
     * contributor 가 없으면 (운영 환경에서 의존이 누락) 보수적으로 false 처리.
     */
    private boolean isContributorUp(String name) {
        HealthContributor contributor = healthRegistry.getContributor(name);
        if (!(contributor instanceof HealthIndicator indicator)) {
            return false;
        }
        Health health = indicator.health();
        return "UP".equals(health.getStatus().getCode());
    }
}
