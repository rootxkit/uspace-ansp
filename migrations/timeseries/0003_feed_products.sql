-- feed_products: what manned-feed served to whom, sampled at 0.1 Hz per
-- client (docs/PLAN.md section 5.2; the Annex V record of the
-- exchange). It describes the samples of manned_tracks and is kept as
-- long as they are: 1-day chunks, dropped after 90 days. ansp_ts_app may
-- SELECT and INSERT only.

-- +goose Up
CREATE TABLE feed_products (
    at              timestamptz NOT NULL,
    client_id       text        NOT NULL CHECK (client_id <> ''),
    tracks_sent     integer     NOT NULL CHECK (tracks_sent >= 0),
    tracks_relevant integer     NOT NULL CHECK (tracks_relevant >= 0 AND tracks_relevant <= tracks_sent),
    degraded        text[]      NOT NULL DEFAULT '{}',
    policy_version  bigint      NOT NULL CHECK (policy_version >= 0)
);

SELECT create_hypertable('feed_products', by_range('at', INTERVAL '1 day'));

CREATE INDEX feed_products_client_idx ON feed_products (client_id, at DESC);

SELECT add_retention_policy('feed_products', INTERVAL '90 days');

GRANT SELECT, INSERT ON feed_products TO ansp_ts_app;

-- +goose Down
SELECT remove_retention_policy('feed_products', if_exists => true);
DROP TABLE IF EXISTS feed_products;
