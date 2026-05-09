package com.example.auth.application.exception;

public class UserAlreadyExistsException extends RuntimeException {

    public UserAlreadyExistsException() {
        super("email already taken");
    }
}
