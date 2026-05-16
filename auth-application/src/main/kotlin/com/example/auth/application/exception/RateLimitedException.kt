package com.example.auth.application.exception

/** brute-force 의심 — 짧은 시간에 너무 많은 시도. */
class RateLimitedException : RuntimeException("too many requests")
