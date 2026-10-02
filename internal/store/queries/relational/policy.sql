-- WP-1: the ansp_policy rows (internal/policy through store.PolicyRepo).

-- name: LatestPolicy :one
SELECT * FROM ansp_policy ORDER BY policy_version DESC LIMIT 1;

-- name: InsertPolicy :one
INSERT INTO ansp_policy (
    feed_margin_lateral_m, feed_margin_vertical_m, stale_after_s,
    source_liveness_s, cisp_alarm_after_s, cisp_heartbeat_s,
    cis_reconcile_s, cis_stale_bound_s, notice_escalation_s,
    default_zone_type, country, changed_by, changed_at
) VALUES (
    sqlc.arg(feed_margin_lateral_m), sqlc.arg(feed_margin_vertical_m), sqlc.arg(stale_after_s),
    sqlc.arg(source_liveness_s), sqlc.arg(cisp_alarm_after_s), sqlc.arg(cisp_heartbeat_s),
    sqlc.arg(cis_reconcile_s), sqlc.arg(cis_stale_bound_s), sqlc.arg(notice_escalation_s),
    sqlc.arg(default_zone_type), sqlc.arg(country), sqlc.arg(changed_by), clock_timestamp()
)
RETURNING *;
