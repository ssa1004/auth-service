-- V3 — Social Login (OIDC consumer) skeleton (ADR-0013).
--
-- 외부 IdP (Google / Microsoft / GitHub OIDC) 로 로그인한 사용자의 매핑 테이블.
-- (provider, provider_user_id) 가 globally unique — 사용자가 IdP 측 계정을 옮기지 않는 한
-- 한 row 만 존재. user_id 는 사용자 도메인의 User.id 를 그대로 참조.

CREATE TABLE external_identities (
    id                  UUID        PRIMARY KEY,
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- 'google', 'microsoft', 'github' 등. enum 안 쓰는 이유 — 새 vendor 추가가 잦고
    -- DDL 변경 비용 회피.
    provider            TEXT        NOT NULL,
    -- IdP 측 user 의 sub (Google 의 numeric ID 등). 이메일은 변할 수 있어 sub 가 더 안전.
    provider_user_id    TEXT        NOT NULL,
    -- 가입 시점 IdP 가 알려준 이메일 — 운영 사고 추적용 (실제 매핑은 user_id 기준).
    email_at_link       TEXT,
    linked_at           TIMESTAMPTZ NOT NULL,
    -- 마지막으로 OIDC 로 로그인한 시점.
    last_login_at       TIMESTAMPTZ,

    CONSTRAINT external_identities_provider_subject_uq
        UNIQUE (provider, provider_user_id)
);

CREATE INDEX external_identities_user_id_idx ON external_identities(user_id);
