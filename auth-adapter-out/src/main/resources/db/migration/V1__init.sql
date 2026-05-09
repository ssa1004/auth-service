-- 초기 스키마. PostgreSQL 16+.
--
-- 보안 결정 (ADR-0006): tenant_id 는 모든 테이블에 명시 + index. 격리는 application
-- 레벨에서 강제하며 RLS 는 후속 ADR.

CREATE TABLE tenants (
    id              UUID        PRIMARY KEY,
    slug            TEXT        NOT NULL UNIQUE,
    display_name    TEXT        NOT NULL,
    status          TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE users (
    id              UUID        PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    email           TEXT        NOT NULL,
    -- BCrypt cost=12 결과. 평문 비밀번호 컬럼 추가 금지.
    password_hash   TEXT        NOT NULL,
    status          TEXT        NOT NULL,
    mfa_status      TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    -- (tenant_id, email) 단위 unique — 같은 이메일이라도 다른 테넌트면 별개.
    CONSTRAINT users_tenant_email_uq UNIQUE (tenant_id, email)
);
CREATE INDEX users_tenant_id_idx ON users(tenant_id);

CREATE TABLE roles (
    id              UUID        PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    slug            TEXT        NOT NULL,
    display_name    TEXT        NOT NULL,
    CONSTRAINT roles_tenant_slug_uq UNIQUE (tenant_id, slug)
);

CREATE TABLE role_permissions (
    role_id         UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission      TEXT        NOT NULL,
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE user_roles (
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id         UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE refresh_tokens (
    id              UUID        PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    user_id         UUID        NOT NULL REFERENCES users(id),
    -- SHA-256 hex (64자). 평문 token 절대 저장 금지.
    token_hash      TEXT        NOT NULL UNIQUE,
    parent_id       UUID        REFERENCES refresh_tokens(id),
    status          TEXT        NOT NULL,
    device_label    TEXT,
    ip_address      TEXT,
    issued_at       TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX refresh_tokens_user_active_idx
    ON refresh_tokens(tenant_id, user_id) WHERE status = 'ACTIVE';
CREATE INDEX refresh_tokens_expires_idx ON refresh_tokens(expires_at);

CREATE TABLE mfa_secrets (
    id              UUID        PRIMARY KEY,
    user_id         UUID        NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    -- AES 암호화된 base32 secret. 평문 컬럼 추가 금지.
    secret_cipher   TEXT        NOT NULL,
    method          TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    confirmed_at    TIMESTAMPTZ
);

CREATE TABLE audit_events (
    id              UUID        PRIMARY KEY,
    tenant_id       UUID        NOT NULL,
    user_id         UUID,
    type            TEXT        NOT NULL,
    ip_address      TEXT,
    user_agent      TEXT,
    payload_json    TEXT        NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX audit_events_tenant_user_time_idx
    ON audit_events(tenant_id, user_id, occurred_at DESC);
CREATE INDEX audit_events_type_time_idx
    ON audit_events(type, occurred_at DESC);
-- audit 는 append-only — UPDATE / DELETE 권한은 운영 DB role 에서 회수합니다.
