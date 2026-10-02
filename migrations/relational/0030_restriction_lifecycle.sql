-- The restriction state machine of WP-5 (docs/WORKPACKAGES/WP-5.md) on
-- top of WP-1's tables (0005):
--
-- restrictions gains activate_at (a planned restriction waiting for the
-- ticker to activate it at starts_at; only a planned one has it),
-- bus_version (the newest version on the restr.v1 stream: every version
-- above it is republished by the ticker, so a failed publish is repaired
-- and never lost), the console's Idempotency-Key per account with the
-- SHA-256 of the body it was sent with, and the CIS version the
-- restriction was placed against with when that projection was fetched
-- (the answer's cis_version and cis_age_s, the age on the database's
-- clock).
--
-- restriction_versions gains what the restr.v1 message of a version
-- needs to be rebuilt the same way however often it is republished:
-- its state, window and envelope msg_id.
--
-- restriction_requests gains the requester's client_ref (unique per
-- requester: a repeat answers the first request) and the SHA-256 of the
-- payload (a different payload under the same ref is refused).
--
-- Identifiers (D4: DAR plus 4 base-36 characters) are drawn from
-- restriction_identifier_seq, which never cycles: an identifier names one
-- restriction for ever. internal/restriction.Identifier permutes the
-- value with restriction_identifier_key's offset, chosen at random when
-- this migration runs, so that a database built afresh (a lab reset)
-- does not hand the CISP identifiers it already holds.

-- +goose Up
ALTER TABLE restrictions
    ADD COLUMN activate_at        timestamptz,
    ADD COLUMN bus_version        bigint NOT NULL DEFAULT 0 CHECK (bus_version >= 0),
    ADD COLUMN idempotency_actor  text CHECK (idempotency_actor <> '' AND length(idempotency_actor) <= 256),
    ADD COLUMN idempotency_key    text CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
    ADD COLUMN idempotency_sha256 text CHECK (idempotency_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN cis_version        text CHECK (length(cis_version) <= 128),
    ADD CONSTRAINT restrictions_activate_planned CHECK (activate_at IS NULL OR state = 'planned'),
    ADD CONSTRAINT restrictions_bus_le_version CHECK (bus_version <= ansp_version),
    ADD CONSTRAINT restrictions_idempotency_whole CHECK (
        (idempotency_key IS NULL) = (idempotency_actor IS NULL)
        AND (idempotency_key IS NULL) = (idempotency_sha256 IS NULL)
    ),
    ADD CONSTRAINT restrictions_idempotency_unique UNIQUE (idempotency_actor, idempotency_key);

CREATE INDEX restrictions_due_activation_idx ON restrictions (activate_at) WHERE state = 'planned' AND activate_at IS NOT NULL;
CREATE INDEX restrictions_due_expiry_idx ON restrictions (ends_at) WHERE state = 'active';
CREATE INDEX restrictions_unpublished_idx ON restrictions (id) WHERE bus_version < ansp_version;
CREATE INDEX restrictions_supersedes_idx ON restrictions (supersedes_id) WHERE supersedes_id IS NOT NULL;
CREATE INDEX restrictions_created_idx ON restrictions (created_at DESC, id DESC);

ALTER TABLE restriction_versions
    ADD COLUMN state     restriction_state NOT NULL,
    ADD COLUMN starts_at timestamptz NOT NULL,
    ADD COLUMN ends_at   timestamptz NOT NULL,
    ADD COLUMN msg_id    text NOT NULL CHECK (msg_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    ADD CONSTRAINT restriction_versions_window CHECK (ends_at >= starts_at),
    ADD CONSTRAINT restriction_versions_msg_id_unique UNIQUE (msg_id);

ALTER TABLE restriction_requests
    ADD COLUMN client_ref     text NOT NULL CHECK (client_ref <> '' AND length(client_ref) <= 128),
    ADD COLUMN payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT restriction_requests_client_ref_unique UNIQUE (requester, client_ref),
    ADD CONSTRAINT restriction_requests_payload_bound CHECK (octet_length(payload::text) <= 262144);

CREATE INDEX restriction_requests_open_idx ON restriction_requests (requester) WHERE state = 'received';

CREATE SEQUENCE restriction_identifier_seq AS bigint MINVALUE 0 MAXVALUE 1679615 START 0 NO CYCLE;

CREATE TABLE restriction_identifier_key (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    offset_n  bigint  NOT NULL CHECK (offset_n >= 0 AND offset_n < 1679616)
);
INSERT INTO restriction_identifier_key (offset_n) VALUES (floor(random() * 1679616)::bigint);

GRANT USAGE ON SEQUENCE restriction_identifier_seq TO ansp_app;
GRANT SELECT ON restriction_identifier_key TO ansp_app;

-- +goose Down
DROP TABLE IF EXISTS restriction_identifier_key;
DROP SEQUENCE IF EXISTS restriction_identifier_seq;
DROP INDEX IF EXISTS restriction_requests_open_idx;
ALTER TABLE restriction_requests
    DROP CONSTRAINT IF EXISTS restriction_requests_payload_bound,
    DROP CONSTRAINT IF EXISTS restriction_requests_client_ref_unique,
    DROP COLUMN IF EXISTS payload_sha256,
    DROP COLUMN IF EXISTS client_ref;
ALTER TABLE restriction_versions
    DROP CONSTRAINT IF EXISTS restriction_versions_msg_id_unique,
    DROP CONSTRAINT IF EXISTS restriction_versions_window,
    DROP COLUMN IF EXISTS msg_id,
    DROP COLUMN IF EXISTS ends_at,
    DROP COLUMN IF EXISTS starts_at,
    DROP COLUMN IF EXISTS state;
DROP INDEX IF EXISTS restrictions_created_idx;
DROP INDEX IF EXISTS restrictions_supersedes_idx;
DROP INDEX IF EXISTS restrictions_unpublished_idx;
DROP INDEX IF EXISTS restrictions_due_expiry_idx;
DROP INDEX IF EXISTS restrictions_due_activation_idx;
ALTER TABLE restrictions
    DROP CONSTRAINT IF EXISTS restrictions_idempotency_unique,
    DROP CONSTRAINT IF EXISTS restrictions_idempotency_whole,
    DROP CONSTRAINT IF EXISTS restrictions_bus_le_version,
    DROP CONSTRAINT IF EXISTS restrictions_activate_planned,
    DROP COLUMN IF EXISTS cis_version,
    DROP COLUMN IF EXISTS idempotency_sha256,
    DROP COLUMN IF EXISTS idempotency_key,
    DROP COLUMN IF EXISTS idempotency_actor,
    DROP COLUMN IF EXISTS bus_version,
    DROP COLUMN IF EXISTS activate_at;
