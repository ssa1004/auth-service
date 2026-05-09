package com.example.auth.domain.role;

import java.util.Objects;

/**
 * 가장 잘게 쪼갠 권한 단위. 형식은 {@code resource:action} (예: {@code billing:read}).
 *
 * <p>RBAC 에서 grant 단위는 Role 이지만, JWT claim 에는 user 가 받은 모든 Role 의
 * permission 합집합을 담습니다. 이렇게 하면 검증 측 (consumer service) 은 role lookup
 * 없이 permission 만으로 인가 결정을 내릴 수 있습니다.
 */
public record Permission(String name) {

    public Permission {
        Objects.requireNonNull(name, "permission name 은 null 일 수 없습니다");
        if (!name.matches("[a-z][a-z0-9_]*:[a-z][a-z0-9_]*")) {
            throw new IllegalArgumentException(
                    "permission 형식은 'resource:action' 이어야 합니다: " + name);
        }
    }

    public static Permission of(String name) {
        return new Permission(name);
    }
}
