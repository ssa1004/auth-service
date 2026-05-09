package com.example.auth.domain.common;

import java.util.Objects;
import java.util.UUID;

/**
 * 사용자 식별자. JWT subject ({@code sub}) 로도 사용됩니다.
 */
public record UserId(UUID value) {

    public UserId {
        Objects.requireNonNull(value, "user id 는 null 일 수 없습니다");
    }

    public static UserId of(UUID value) {
        return new UserId(value);
    }

    public static UserId of(String value) {
        return new UserId(UUID.fromString(value));
    }

    public static UserId newId() {
        return new UserId(UUID.randomUUID());
    }

    public String asString() {
        return value.toString();
    }
}
