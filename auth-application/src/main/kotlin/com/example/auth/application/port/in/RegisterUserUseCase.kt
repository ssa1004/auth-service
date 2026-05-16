package com.example.auth.application.port.`in`

import com.example.auth.domain.common.UserId
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

interface RegisterUserUseCase {

    fun register(cmd: Command): UserId

    @JvmRecord
    data class Command(
        @field:NotBlank val tenantSlug: String,
        @field:NotBlank @field:Email val email: String,
        @field:NotBlank @field:Size(min = 12, max = 128) val rawPassword: String,
        val ipAddress: String?,
    ) {
        // 정책: 최소 12자. 별도 복잡도 요구는 두지 않음 (NIST SP 800-63B 권고).

        /** ipAddress 가 의미 없는 단위 테스트 / 내부 호출용 단축 생성자. */
        constructor(tenantSlug: String, email: String, rawPassword: String) :
            this(tenantSlug, email, rawPassword, null)
    }
}
