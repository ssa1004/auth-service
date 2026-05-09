package com.example.auth.adapter.out.mail;

import com.example.auth.application.port.out.VerificationMailSender;
import com.example.auth.domain.common.EmailMasker;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

/**
 * Mailhog (개발) 또는 운영 SMTP 로 verification 메일 발송. 본 단계에서는 mock 으로 충분 —
 * verification token 의 생성/검증 흐름은 후속 ADR (이메일 verification) 에서 다룹니다.
 *
 * <p>로그에는 *마스킹된* email 만 출력합니다.
 */
@Slf4j
@Component
public class SmtpVerificationMailSenderAdapter implements VerificationMailSender {

    private final JavaMailSender sender;
    private final String from;

    public SmtpVerificationMailSenderAdapter(
            JavaMailSender sender,
            @Value("${auth.mail.from:no-reply@auth.example.com}") String from) {
        this.sender = sender;
        this.from = from;
    }

    @Override
    public void sendVerification(String email, String verificationLink) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(email);
        message.setSubject("[auth-service] 이메일 인증");
        message.setText("아래 링크를 클릭하여 이메일을 인증해 주세요.\n\n" + verificationLink);
        try {
            sender.send(message);
            log.info("verification mail sent to={}", EmailMasker.mask(email));
        } catch (Exception e) {
            // 메일 실패가 회원가입 트랜잭션을 막지 않도록 — verification 은 사용자가 재요청 가능.
            log.warn("verification mail send failed to={} reason={}",
                    EmailMasker.mask(email), e.getMessage());
        }
    }
}
