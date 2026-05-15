package com.example.auth.domain.mfa

enum class MfaMethod {
    /** RFC 6238 Time-based OTP. Google Authenticator / Authy 호환. ADR-0007 결정. */
    TOTP,

    /** WebAuthn / FIDO2. 후속 ADR. 현재 미구현. */
    WEBAUTHN,
}
