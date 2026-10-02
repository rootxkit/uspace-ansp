-- WP-2: console accounts, their mandatory TOTP, the sign-in challenge
-- between the password and the code, the per-username lockout, the
-- sessions, and the machine clients this system has served
-- (docs/PLAN.md section 5.1, spec 01 section 4 users, 06 section 3).
--
-- users: a lower-case username, the argon2id PHC string of the password,
-- one role of watch_supervisor, viewer or admin, a status, and
-- oidc_subject reserved for an OIDC login (01 section 4: OIDC-ready;
-- nothing reads it yet).
--
-- user_mfa: the TOTP secret sealed with AES-256-GCM under
-- ANSP_SECRETS_KEY_FILE (key_id names the key), enrolled_at NULL while
-- the enrolment is pending, and last_step, the last RFC 6238 time step
-- accepted: a code is accepted once (internal/auth locks the row FOR
-- UPDATE to compare and move it).
--
-- login_challenges: the mfa_pending token of POST /v1/auth/login, stored
-- by its SHA-256 only, single use, short-lived, with a bounded number of
-- codes. login_lockouts: failures per username (known or not, so the
-- lockout says nothing about whether an account exists), held here so
-- the lockout is the same on every api replica.
--
-- user_sessions: one row per session token (jti = the session id), so
-- logout and revocation work and the idle timeout is enforced.
--
-- oauth_clients_seen: an observation log of machine clients (the truth
-- is the authority's token service), written off the request path.
--
-- Every instant is written from the database clock by internal/store.
-- The sweep deletes expired challenges and sessions and stale lockouts,
-- so every table is bounded by the sign-in rate times a lifetime (E-10).

-- +goose Up
CREATE TABLE users (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    username      text        NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9._@-]{2,63}$'),
    password_hash text        NOT NULL CHECK (password_hash LIKE '$argon2id$%' AND length(password_hash) <= 512),
    role          text        NOT NULL CHECK (role IN ('watch_supervisor', 'viewer', 'admin')),
    status        text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    oidc_subject  text        UNIQUE CHECK (length(oidc_subject) BETWEEN 1 AND 255),
    created_at    timestamptz NOT NULL,
    created_by    text        NOT NULL CHECK (created_by <> '' AND length(created_by) <= 256),
    updated_at    timestamptz NOT NULL,
    updated_by    text        NOT NULL CHECK (updated_by <> '' AND length(updated_by) <= 256),
    last_login_at timestamptz
);

CREATE TABLE user_mfa (
    user_id     uuid        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    key_id      text        NOT NULL CHECK (key_id ~ '^[0-9a-f]{16}$'),
    secret_enc  bytea       NOT NULL CHECK (length(secret_enc) BETWEEN 28 AND 256),
    enrolled_at timestamptz,
    last_step   bigint      NOT NULL DEFAULT 0 CHECK (last_step >= 0),
    updated_at  timestamptz NOT NULL
);

CREATE TABLE login_challenges (
    token_hash text        PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    attempts   integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    used_at    timestamptz,
    remote_ip  text        NOT NULL DEFAULT '' CHECK (length(remote_ip) <= 64),
    CONSTRAINT login_challenges_expiry CHECK (expires_at > created_at)
);

CREATE INDEX login_challenges_expires_idx ON login_challenges (expires_at);

CREATE TABLE login_lockouts (
    username     text        PRIMARY KEY CHECK (username ~ '^[a-z0-9][a-z0-9._@-]{2,63}$'),
    failures     integer     NOT NULL DEFAULT 0 CHECK (failures >= 0),
    locked_until timestamptz,
    updated_at   timestamptz NOT NULL
);

CREATE INDEX login_lockouts_updated_idx ON login_lockouts (updated_at);

CREATE TABLE user_sessions (
    jti           text        PRIMARY KEY CHECK (jti ~ '^[0-9a-f]{32}$'),
    user_id       uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role          text        NOT NULL CHECK (role IN ('watch_supervisor', 'viewer', 'admin')),
    issued_at     timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    revoked_at    timestamptz,
    revoke_reason text        CHECK (length(revoke_reason) BETWEEN 1 AND 64),
    remote_ip     text        NOT NULL DEFAULT '' CHECK (length(remote_ip) <= 64),
    user_agent    text        NOT NULL DEFAULT '' CHECK (length(user_agent) <= 256),
    CONSTRAINT user_sessions_expiry CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '12 hours'),
    CONSTRAINT user_sessions_revocation CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);

CREATE INDEX user_sessions_user_live_idx ON user_sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX user_sessions_expires_idx ON user_sessions (expires_at);

CREATE TABLE oauth_clients_seen (
    client_id     text        PRIMARY KEY CHECK (client_id <> '' AND length(client_id) <= 256),
    system        text        CHECK (system IN ('ussp', 'cisp', 'authority', 'lab')),
    issuer        text        NOT NULL CHECK (issuer <> '' AND length(issuer) <= 512),
    mtls_subject  text        CHECK (length(mtls_subject) <= 1024),
    first_seen_at timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    scopes_seen   text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(scopes_seen) <= 64)
);

GRANT SELECT, INSERT, UPDATE ON users, user_mfa, login_challenges, login_lockouts, user_sessions, oauth_clients_seen TO ansp_app;
GRANT DELETE ON user_mfa, login_challenges, login_lockouts, user_sessions TO ansp_app;

-- +goose Down
DROP TABLE IF EXISTS oauth_clients_seen;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS login_lockouts;
DROP TABLE IF EXISTS login_challenges;
DROP TABLE IF EXISTS user_mfa;
DROP TABLE IF EXISTS users;
