package com.example.auth.adapter.out.mail

import com.example.auth.application.port.out.VerificationMailSender
import com.example.auth.domain.common.EmailMasker
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.mail.SimpleMailMessage
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.stereotype.Component

/**
 * Mailhog (개발) 또는 운영 SMTP 로 verification 메일 발송. 본 단계에서는 mock 으로 충분 —
 * verification token 의 생성/검증 흐름은 후속 ADR (이메일 verification) 에서 다룹니다.
 *
 * 로그에는 *마스킹된* email 만 출력합니다.
 */
@Component
class SmtpVerificationMailSenderAdapter(
    private val sender: JavaMailSender,
    @Value("\${auth.mail.from:no-reply@auth.example.com}") private val from: String,
) : VerificationMailSender {

    override fun sendVerification(email: String, verificationLink: String) {
        val message = SimpleMailMessage()
        message.from = from
        message.setTo(email)
        message.subject = "[auth-service] 이메일 인증"
        message.text = "아래 링크를 클릭하여 이메일을 인증해 주세요.\n\n$verificationLink"
        try {
            sender.send(message)
            log.info("verification mail sent to={}", EmailMasker.mask(email))
        } catch (e: Exception) {
            // 메일 실패가 회원가입 트랜잭션을 막지 않도록 — verification 은 사용자가 재요청 가능.
            log.warn(
                "verification mail send failed to={} reason={}",
                EmailMasker.mask(email), e.message,
            )
        }
    }

    private companion object {
        val log = LoggerFactory.getLogger(SmtpVerificationMailSenderAdapter::class.java)
    }
}
