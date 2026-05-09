# ADR (Architecture Decision Record)

각 ADR 은 *왜 그 결정을 했는지* 한 문서에 정리합니다 (배경 / 결정 / 대안 / 결과 / 후속).
짧게 읽고도 결정과 장단점을 파악할 수 있는 분량을 목표로 합니다.

| 번호 | 제목 |
| --- | --- |
| [0001](0001-hexagonal-and-spring-authorization-server.md) | Hexagonal architecture + Spring Authorization Server |
| [0002](0002-rs256-vs-eddsa.md) | JWK 알고리즘 — RS256 vs EdDSA |
| [0003](0003-jwk-rotation-strategy.md) | JWK rotation 전략 (24h cycle + grace) |
| [0004](0004-refresh-token-rotation-and-reuse-detection.md) | Refresh token rotation + reuse detection |
| [0005](0005-rbac-vs-abac.md) | RBAC vs ABAC |
| [0006](0006-multi-tenant-data-isolation.md) | Multi-tenant 데이터 격리 (JWT claim + query filter) |
| [0007](0007-mfa-totp-vs-sms-webauthn.md) | 2FA — TOTP 선택 (vs SMS / Email / WebAuthn) |
| [0008](0008-audit-log-append-only.md) | Audit log append-only |
| [0009](0009-hikaricp-tuning-and-leak-detection.md) | HikariCP 튜닝 + connection leak detection |
| [0010](0010-k8s-three-probes-and-readiness-coordinator.md) | K8s 3종 probe (liveness / readiness / startup) |
| [0011](0011-graceful-shutdown.md) | Graceful shutdown (SIGTERM → in-flight 처리) |
| [0012](0012-audit-siem-outbox.md) | Audit log SIEM Kafka sink |
| [0013](0013-social-login-oidc-skeleton.md) | Social login (Google OIDC consumer) |
| [0014](0014-key-material-source-abstraction.md) | JWK 외부 KMS 추상화 (`KeyMaterialSource`) |
| [0015](0015-refresh-reuse-grace-window.md) | Refresh reuse race grace window |
| [0016](0016-opa-policy-decision.md) | OPA (Open Policy Agent) ABAC 정책 엔진 |
| [0017](0017-token-introspection-rfc-7662.md) | RFC 7662 Token Introspection endpoint |
| [0018](0018-token-revocation-rfc-7009.md) | RFC 7009 Token Revocation endpoint |
