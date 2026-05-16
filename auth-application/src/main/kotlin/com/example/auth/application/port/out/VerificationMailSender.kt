package com.example.auth.application.port.out

/**
 * 이메일 verification token 발송 port. 구현체는 Mailhog SMTP (개발) 또는 운영 SES.
 */
interface VerificationMailSender {

    fun sendVerification(email: String, verificationLink: String)
}
