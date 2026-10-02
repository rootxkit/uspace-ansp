-- adapters: the registry of surveillance feeds (docs/PLAN.md section
-- 5.1). config holds only non-secret settings; the running state comes
-- from src.v1.manned.<id> and is written here by api as a snapshot.

-- +goose Up
CREATE TABLE adapters (
    id             text        PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    kind           text        NOT NULL CHECK (kind IN ('replay', 'dump1090_sbs', 'dump1090_json', 'asterix_cat021', 'atm_api')),
    display_name   text        NOT NULL CHECK (display_name <> '' AND length(display_name) <= 200),
    source_class   text        NOT NULL CHECK (source_class IN ('ads_b', 'mode_s', 'ssr', 'atm_feed', 'ads_l')),
    config         jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(config) = 'object'),
    status         text        NOT NULL DEFAULT 'configured' CHECK (status IN ('configured', 'running', 'silent', 'disabled')),
    last_frame_at  timestamptz,
    last_status_at timestamptz,
    counters       jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(counters) = 'object')
);

GRANT SELECT, INSERT, UPDATE ON adapters TO ansp_app;

-- +goose Down
DROP TABLE IF EXISTS adapters;
