package com.example.auth.application.exception;

/** brute-force 의심 — 짧은 시간에 너무 많은 시도. */
public class RateLimitedException extends RuntimeException {

    public RateLimitedException() {
        super("too many requests");
    }
}
