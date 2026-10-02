-- WP-2: console accounts, MFA, sign-in challenges, lockouts, sessions
-- and the machine clients seen (migration 0020). Every instant a query
-- compares or writes is passed in from DBNow or read from
-- clock_timestamp() here: the database clock, never a process clock.

-- name: UserByUsername :one
SELECT * FROM users WHERE username = sqlc.arg(username);

-- name: UserByID :one
SELECT * FROM users WHERE id = sqlc.arg(id);

-- name: UserForUpdate :one
-- Locks the account row to the end of the transaction.
SELECT * FROM users WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListUsers :many
SELECT * FROM users ORDER BY username LIMIT sqlc.arg(max_rows);

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: CountActiveAdmins :one
SELECT count(*) FROM users WHERE role = 'admin' AND status = 'active';

-- name: InsertUser :one
INSERT INTO users (username, password_hash, role, created_at, created_by, updated_at, updated_by)
VALUES (sqlc.arg(username), sqlc.arg(password_hash), sqlc.arg(role), sqlc.arg(at), sqlc.arg(actor), sqlc.arg(at), sqlc.arg(actor))
RETURNING *;

-- name: SetUserStatus :one
UPDATE users SET status = sqlc.arg(status), updated_at = sqlc.arg(at), updated_by = sqlc.arg(actor)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: TouchUserLogin :exec
UPDATE users SET last_login_at = sqlc.arg(at) WHERE id = sqlc.arg(id);

-- name: UserMFAForUpdate :one
-- Locks the MFA row: two sign-ins with one code race to one winner.
SELECT * FROM user_mfa WHERE user_id = sqlc.arg(user_id) FOR UPDATE;

-- name: UpsertUserMFA :exec
INSERT INTO user_mfa (user_id, key_id, secret_enc, enrolled_at, last_step, updated_at)
VALUES (sqlc.arg(user_id), sqlc.arg(key_id), sqlc.arg(secret_enc), sqlc.narg(enrolled_at), sqlc.arg(last_step), sqlc.arg(at))
ON CONFLICT (user_id) DO UPDATE SET
    key_id = EXCLUDED.key_id, secret_enc = EXCLUDED.secret_enc, enrolled_at = EXCLUDED.enrolled_at,
    last_step = EXCLUDED.last_step, updated_at = EXCLUDED.updated_at;

-- name: DeleteUserMFA :execrows
DELETE FROM user_mfa WHERE user_id = sqlc.arg(user_id);

-- name: InsertChallenge :exec
INSERT INTO login_challenges (token_hash, user_id, created_at, expires_at, remote_ip)
VALUES (sqlc.arg(token_hash), sqlc.arg(user_id), sqlc.arg(at), sqlc.arg(expires_at), sqlc.arg(remote_ip));

-- name: ChallengeForUpdate :one
SELECT * FROM login_challenges WHERE token_hash = sqlc.arg(token_hash) FOR UPDATE;

-- name: CountChallengeAttempt :exec
UPDATE login_challenges SET attempts = attempts + 1 WHERE token_hash = sqlc.arg(token_hash);

-- name: UseChallenge :exec
UPDATE login_challenges SET used_at = sqlc.arg(at) WHERE token_hash = sqlc.arg(token_hash);

-- name: EnsureLockout :exec
INSERT INTO login_lockouts (username, updated_at) VALUES (sqlc.arg(username), sqlc.arg(at))
ON CONFLICT (username) DO NOTHING;

-- name: LockoutForUpdate :one
SELECT * FROM login_lockouts WHERE username = sqlc.arg(username) FOR UPDATE;

-- name: LockoutByUsername :one
SELECT * FROM login_lockouts WHERE username = sqlc.arg(username);

-- name: SetLockout :exec
UPDATE login_lockouts SET failures = sqlc.arg(failures), locked_until = sqlc.narg(locked_until), updated_at = sqlc.arg(at)
WHERE username = sqlc.arg(username);

-- name: ClearLockout :exec
DELETE FROM login_lockouts WHERE username = sqlc.arg(username);

-- name: InsertSession :exec
INSERT INTO user_sessions (jti, user_id, role, issued_at, expires_at, last_seen_at, remote_ip, user_agent)
VALUES (sqlc.arg(jti), sqlc.arg(user_id), sqlc.arg(role), sqlc.arg(issued_at), sqlc.arg(expires_at), sqlc.arg(issued_at),
        sqlc.arg(remote_ip), sqlc.arg(user_agent));

-- name: SessionWithClock :one
-- The session row and the database clock to judge it by.
SELECT s.*, clock_timestamp()::timestamptz AS db_now FROM user_sessions s WHERE s.jti = sqlc.arg(jti);

-- name: TouchSession :exec
UPDATE user_sessions SET last_seen_at = clock_timestamp()
WHERE jti = sqlc.arg(jti) AND revoked_at IS NULL;

-- name: RevokeSession :execrows
UPDATE user_sessions SET revoked_at = sqlc.arg(at), revoke_reason = sqlc.arg(reason)
WHERE jti = sqlc.arg(jti) AND revoked_at IS NULL;

-- name: RevokeUserSessions :many
UPDATE user_sessions SET revoked_at = sqlc.arg(at), revoke_reason = sqlc.arg(reason)
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL
RETURNING jti;

-- name: DeleteExpiredSessions :execrows
DELETE FROM user_sessions WHERE expires_at < sqlc.arg(before);

-- name: DeleteExpiredChallenges :execrows
DELETE FROM login_challenges WHERE expires_at < sqlc.arg(before);

-- name: DeleteStaleLockouts :execrows
-- A lockout row untouched since before and holding no lock.
DELETE FROM login_lockouts
WHERE updated_at < sqlc.arg(before) AND (locked_until IS NULL OR locked_until < sqlc.arg(now));

-- name: UpsertClientSeen :exec
-- First and last seen, the subject of the client certificate when one
-- was bound, and the union of the scopes seen, capped at 64.
INSERT INTO oauth_clients_seen (client_id, system, issuer, mtls_subject, first_seen_at, last_seen_at, scopes_seen)
VALUES (sqlc.arg(client_id), sqlc.narg(system), sqlc.arg(issuer), sqlc.narg(mtls_subject), sqlc.arg(first_seen_at),
        sqlc.arg(last_seen_at), (SELECT coalesce(array_agg(s ORDER BY s), '{}') FROM (SELECT DISTINCT unnest(sqlc.arg(scopes)::text[]) AS s ORDER BY 1 LIMIT 64) n))
ON CONFLICT (client_id) DO UPDATE SET
    system        = coalesce(EXCLUDED.system, oauth_clients_seen.system),
    issuer        = EXCLUDED.issuer,
    mtls_subject  = coalesce(EXCLUDED.mtls_subject, oauth_clients_seen.mtls_subject),
    first_seen_at = least(oauth_clients_seen.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at  = greatest(oauth_clients_seen.last_seen_at, EXCLUDED.last_seen_at),
    scopes_seen   = (SELECT coalesce(array_agg(s ORDER BY s), '{}')
                     FROM (SELECT DISTINCT unnest(oauth_clients_seen.scopes_seen || EXCLUDED.scopes_seen) AS s ORDER BY 1 LIMIT 64) m);

-- name: ClientSeen :one
SELECT * FROM oauth_clients_seen WHERE client_id = sqlc.arg(client_id);
