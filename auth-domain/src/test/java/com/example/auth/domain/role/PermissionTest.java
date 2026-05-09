package com.example.auth.domain.role;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class PermissionTest {

    @Test
    void resource_action_형식만_허용() {
        assertThat(Permission.of("billing:read").name()).isEqualTo("billing:read");
        assertThat(Permission.of("user_profile:write_all").name()).isEqualTo("user_profile:write_all");
    }

    @Test
    void 잘못된_형식은_거부() {
        assertThatThrownBy(() -> Permission.of("billing"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Permission.of("Billing:read"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Permission.of(":read"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Permission.of("billing:"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
