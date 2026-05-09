package com.example.auth.application.exception;

/** 로그인 실패. 사용자 미존재 / 비밀번호 불일치 / 계정 잠김 모두 동일 메시지로 통일. */
public class InvalidCredentialsException extends AuthenticationException {

    public InvalidCredentialsException() {
        super("invalid credentials");
    }
}
