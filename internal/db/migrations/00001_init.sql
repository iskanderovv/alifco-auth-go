-- +goose Up
CREATE TYPE oauth_provider AS ENUM ('google', 'facebook', 'telegram');
CREATE TYPE oauth_mode AS ENUM ('login', 'link');

CREATE TABLE users (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      VARCHAR(320),
    name       VARCHAR(255) NOT NULL,
    avatar_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE oauth_identities (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider         oauth_provider NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    email            VARCHAR(320),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at    TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_identity_provider_subject ON oauth_identities (provider, provider_user_id);
CREATE UNIQUE INDEX uq_identity_user_provider ON oauth_identities (user_id, provider);

CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id  UUID NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    user_agent TEXT,
    ip         INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);
CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens (family_id);

CREATE TABLE oauth_transactions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    state_hash    CHAR(64) NOT NULL UNIQUE,
    code_verifier VARCHAR(128) NOT NULL,
    provider      oauth_provider NOT NULL,
    mode          oauth_mode NOT NULL DEFAULT 'login',
    user_id       UUID REFERENCES users (id) ON DELETE CASCADE,
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE oauth_transactions;
DROP TABLE refresh_tokens;
DROP TABLE oauth_identities;
DROP TABLE users;
DROP TYPE oauth_mode;
DROP TYPE oauth_provider;
