package com.example.auth.application.port.out;

import java.time.Duration;

/**
 * Access JWT 의 즉시 차단 목록 — RFC 7009 admin revoke 와 RFC 7662 introspection 가
 * 같이 동작하기 위한 핵심 (ADR-0017 / 0018).
 *
 * <p>본 IdP 의 access token 은 self-validate JWT 라 일반적으로는 revoke 가 즉시 반영되지
 * 않습니다 (TTL 만료 전까지 유효). 운영자가 강제 revoke 한 token 은 본 blocklist 에
 * 만료 시각까지의 TTL 로 보관하며, introspection 호출 시 이 목록에 있는 jti 는
 * {@code active=false} 로 응답합니다.
 *
 * <p>구현체는 Redis. 본 IdP 가 단일 인스턴스가 아닌 분산 환경에서도 같은 블록리스트를
 * 공유하기 위함.
 */
public interface AccessTokenBlocklist {

    /**
     * jti 를 블록리스트에 추가. ttl 동안 보관 후 자동 만료 — token 자체가 만료된 후에는
     * 굳이 메모리를 차지할 필요가 없음.
     *
     * @param jwtId access JWT 의 {@code jti} claim.
     * @param ttl   token 의 남은 TTL. 0 이하이면 즉시 만료된 token 이라 굳이 추가 X (호출자 판단).
     */
    void add(String jwtId, Duration ttl);

    boolean contains(String jwtId);
}
