-- uspace-ansp bootstrap (deploy/compose.prod.yaml): POSTGRES_DB creates
-- `ansp` (relational); this creates `ansp_ts` (TimescaleDB) beside it in
-- the one container (M37). Extensions and roles are created by the
-- migrations (WP-1).
CREATE DATABASE ansp_ts;
