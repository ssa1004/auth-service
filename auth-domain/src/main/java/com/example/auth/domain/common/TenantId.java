package com.example.auth.domain.common;

import java.util.Objects;
import java.util.UUID;

/**
 * 테넌트 식별자. JWT 의 {@code tnt} claim 에 담기며 모든 도메인 객체가 이 값을 통해
 * 격리됩니다. value object 로 강제하여 raw String/UUID 가 도메인 메서드 시그니처에 노출되지
 * 않도록 합니다.
 */
public record TenantId(UUID value) {

    public TenantId {
        Objects.requireNonNull(value, "tenant id 는 null 일 수 없습니다");
    }

    public static TenantId of(UUID value) {
        return new TenantId(value);
    }

    public static TenantId of(String value) {
        return new TenantId(UUID.fromString(value));
    }

    public static TenantId newId() {
        return new TenantId(UUID.randomUUID());
    }

    public String asString() {
        return value.toString();
    }
}
