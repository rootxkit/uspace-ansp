-- The goose version table of the timeseries tree, as goose v3 creates
-- it outside the tree. Declared for sqlc only (SchemaVersion); never
-- applied.
CREATE TABLE goose_db_version_timeseries (
    id         serial    PRIMARY KEY,
    version_id bigint    NOT NULL,
    is_applied boolean   NOT NULL,
    tstamp     timestamp NOT NULL DEFAULT now()
);
