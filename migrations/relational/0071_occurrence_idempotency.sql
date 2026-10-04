-- WP-12 review: the console's Idempotency-Key on an occurrence report
-- (POST /v1/occurrences), per account, with the SHA-256 of the body it
-- was sent with, as restrictions have it (0030). A repeat with the same
-- key and body answers the report first queued; another body under the
-- key is refused 409. A report sent without a key has none of the three
-- (reports queued before this migration, a client that sends none).

-- +goose Up
ALTER TABLE occurrence_reports
    ADD COLUMN idempotency_actor  text CHECK (idempotency_actor <> '' AND length(idempotency_actor) <= 256),
    ADD COLUMN idempotency_key    text CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
    ADD COLUMN idempotency_sha256 text CHECK (idempotency_sha256 ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT occurrence_reports_idempotency_whole CHECK (
        (idempotency_key IS NULL) = (idempotency_actor IS NULL)
        AND (idempotency_key IS NULL) = (idempotency_sha256 IS NULL)
    ),
    ADD CONSTRAINT occurrence_reports_idempotency_unique UNIQUE (idempotency_actor, idempotency_key);

-- +goose Down
ALTER TABLE occurrence_reports
    DROP CONSTRAINT IF EXISTS occurrence_reports_idempotency_unique,
    DROP CONSTRAINT IF EXISTS occurrence_reports_idempotency_whole,
    DROP COLUMN IF EXISTS idempotency_sha256,
    DROP COLUMN IF EXISTS idempotency_key,
    DROP COLUMN IF EXISTS idempotency_actor;
