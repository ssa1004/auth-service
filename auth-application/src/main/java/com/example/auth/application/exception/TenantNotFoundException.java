package com.example.auth.application.exception;

public class TenantNotFoundException extends RuntimeException {

    public TenantNotFoundException(String hint) {
        super("tenant not found: " + hint);
    }
}
