-- WP-1: restrictions, their versions and restriction requests; WP-5
-- (migration 0030) added the version's state, window and msg_id and the
-- request's client_ref here, and the state transitions in
-- restriction_lifecycle.sql. Geometry crosses as
-- GeoJSON text (store.ParseGeometry, store.GeometryJSON).

-- name: InsertRestriction :one
INSERT INTO restrictions (
    id, ansp_ref, identifier, uspace_airspace_id, zone_type, geom, radius_m,
    lower_m, lower_ref, upper_m, upper_ref, starts_at, ends_at, reason_text,
    created_by, created_at, request_id, dss_constraint_id, supersedes_id
) VALUES (
    sqlc.arg(id), sqlc.arg(ansp_ref), sqlc.arg(identifier), sqlc.arg(uspace_airspace_id), sqlc.arg(zone_type),
    ST_SetSRID(ST_GeomFromGeoJSON(sqlc.arg(geom_geojson)::text), 4326), sqlc.narg(radius_m),
    sqlc.arg(lower_m), sqlc.arg(lower_ref), sqlc.arg(upper_m), sqlc.arg(upper_ref),
    sqlc.arg(starts_at), sqlc.arg(ends_at), sqlc.arg(reason_text),
    sqlc.arg(created_by), clock_timestamp(), sqlc.narg(request_id), sqlc.narg(dss_constraint_id), sqlc.narg(supersedes_id)
)
RETURNING id, ansp_version, created_at;

-- name: RestrictionByID :one
SELECT id, ansp_ref, identifier, uspace_airspace_id, zone_type,
       ST_AsGeoJSON(geom)::text AS geom_geojson, radius_m,
       lower_m, lower_ref, upper_m, upper_ref, starts_at, ends_at, reason_text,
       state, ansp_version, created_by, activated_by, ended_by, cancelled_by,
       created_at, activated_at, ended_at_actual, request_id, published_version,
       dss_constraint_id, dss_ovn, dss_version, supersedes_id
FROM restrictions WHERE id = sqlc.arg(id);

-- name: RestrictionByAnspRef :one
SELECT id, ansp_version, state FROM restrictions WHERE ansp_ref = sqlc.arg(ansp_ref);

-- name: InsertRestrictionVersion :exec
INSERT INTO restriction_versions (restriction_id, version, feature, "constraint", changed_by, changed_at, change_reason,
                                  state, starts_at, ends_at, msg_id)
VALUES (sqlc.arg(restriction_id), sqlc.arg(version), sqlc.arg(feature), sqlc.narg(f3548_constraint),
        sqlc.arg(changed_by), sqlc.arg(changed_at), sqlc.arg(change_reason),
        sqlc.arg(state), sqlc.arg(starts_at), sqlc.arg(ends_at), sqlc.arg(msg_id));

-- name: RestrictionVersions :many
SELECT v.restriction_id, v.version, v.feature, v."constraint", v.changed_by, v.changed_at, v.change_reason,
       v.state, v.starts_at, v.ends_at, v.msg_id, r.ansp_ref
FROM restriction_versions v JOIN restrictions r ON r.id = v.restriction_id
WHERE v.restriction_id = sqlc.arg(restriction_id)
ORDER BY v.version
LIMIT sqlc.arg(page_size);

-- name: InsertRestrictionRequest :one
INSERT INTO restriction_requests (id, requester, source, payload, received_at, client_ref, payload_sha256)
VALUES (sqlc.arg(id), sqlc.arg(requester), sqlc.arg(source), sqlc.arg(payload), sqlc.arg(received_at),
        sqlc.arg(client_ref), sqlc.arg(payload_sha256))
RETURNING *;

-- name: RestrictionRequestByID :one
SELECT * FROM restriction_requests WHERE id = sqlc.arg(id);
