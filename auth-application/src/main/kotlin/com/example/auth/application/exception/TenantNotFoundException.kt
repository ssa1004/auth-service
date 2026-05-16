package com.example.auth.application.exception

class TenantNotFoundException(hint: String) : RuntimeException("tenant not found: $hint")
