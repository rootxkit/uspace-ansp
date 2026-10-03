-- WP-5: the restriction state machine (internal/restriction) on the
-- relational database. Every instant a judgement uses comes from the
-- database's clock (clock_timestamp()), never a replica's. Geometry
-- crosses as GeoJSON text; area and placement are computed on geography
-- (03 conventions).

-- name: NextRestrictionIdentifier :one
SELECT nextval('restriction_identifier_seq')::bigint AS seq,
       (SELECT offset_n FROM restriction_identifier_key)::bigint AS offset_n;

-- name: PlanRestriction :exec
INSERT INTO restrictions (
    id, ansp_ref, identifier, uspace_airspace_id, zone_type, geom, radius_m,
    lower_m, lower_ref, upper_m, upper_ref, starts_at, ends_at, reason_text,
    state, ansp_version, created_by, created_at, request_id, dss_constraint_id, supersedes_id,
    idempotency_actor, idempotency_key, idempotency_sha256, cis_version
) VALUES (
    sqlc.arg(id), sqlc.arg(ansp_ref), sqlc.arg(identifier), sqlc.arg(uspace_airspace_id), sqlc.arg(zone_type),
    ST_SetSRID(ST_GeomFromGeoJSON(sqlc.arg(geom_geojson)::text), 4326), sqlc.narg(radius_m),
    sqlc.arg(lower_m), sqlc.arg(lower_ref), sqlc.arg(upper_m), sqlc.arg(upper_ref),
    sqlc.arg(starts_at), sqlc.arg(ends_at), sqlc.arg(reason_text),
    'planned', 1, sqlc.arg(created_by), sqlc.arg(created_at), sqlc.narg(request_id), sqlc.arg(dss_constraint_id), sqlc.narg(supersedes_id),
    sqlc.narg(idempotency_actor), sqlc.narg(idempotency_key), sqlc.narg(idempotency_sha256), sqlc.narg(cis_version)
);

-- name: RestrictionFull :one
SELECT r.id, r.ansp_ref, r.identifier, r.uspace_airspace_id, r.zone_type,
       ST_AsGeoJSON(r.geom)::text AS geom_geojson, r.radius_m,
       r.lower_m, r.lower_ref, r.upper_m, r.upper_ref, r.starts_at, r.ends_at, r.reason_text,
       r.state, r.ansp_version, r.created_by, r.activated_by, r.ended_by, r.cancelled_by,
       r.created_at, r.activated_at, r.ended_at_actual, r.request_id, r.published_version,
       r.dss_constraint_id, r.dss_version, r.supersedes_id, r.activate_at, r.cis_version,
       v.feature, v."constraint", r.dss_state, r.dss_pending_since, r.dss_reference, r.dss_put_version
FROM restrictions r
JOIN restriction_versions v ON v.restriction_id = r.id AND v.version = r.ansp_version
WHERE r.id = sqlc.arg(id);

-- name: LockRestriction :one
SELECT r.id, r.ansp_ref, r.identifier, r.uspace_airspace_id, r.zone_type,
       ST_AsGeoJSON(r.geom)::text AS geom_geojson, r.radius_m,
       r.lower_m, r.lower_ref, r.upper_m, r.upper_ref, r.starts_at, r.ends_at, r.reason_text,
       r.state, r.ansp_version, r.created_by, r.activated_by, r.ended_by, r.cancelled_by,
       r.created_at, r.activated_at, r.ended_at_actual, r.request_id, r.published_version,
       r.dss_constraint_id, r.dss_version, r.supersedes_id, r.activate_at, r.cis_version,
       v.feature, v."constraint", r.dss_state, r.dss_pending_since, r.dss_reference, r.dss_put_version
FROM restrictions r
JOIN restriction_versions v ON v.restriction_id = r.id AND v.version = r.ansp_version
WHERE r.id = sqlc.arg(id)
FOR UPDATE OF r;

-- name: UpdateRestrictionState :execrows
UPDATE restrictions SET
    state = sqlc.arg(state), ansp_version = sqlc.arg(ansp_version), ends_at = sqlc.arg(ends_at),
    activate_at = sqlc.narg(activate_at), activated_by = sqlc.narg(activated_by), activated_at = sqlc.narg(activated_at),
    ended_by = sqlc.narg(ended_by), ended_at_actual = sqlc.narg(ended_at_actual), cancelled_by = sqlc.narg(cancelled_by)
WHERE id = sqlc.arg(id) AND ansp_version = sqlc.arg(prev_version);

-- name: RestrictionByIdempotency :one
SELECT id, idempotency_sha256::text AS sha256
FROM restrictions
WHERE idempotency_actor = sqlc.arg(actor) AND idempotency_key = sqlc.arg(idempotency_key);

-- name: ListRestrictions :many
SELECT r.id, r.ansp_ref, r.identifier, r.uspace_airspace_id, r.zone_type,
       ST_AsGeoJSON(r.geom)::text AS geom_geojson, r.radius_m,
       r.lower_m, r.lower_ref, r.upper_m, r.upper_ref, r.starts_at, r.ends_at, r.reason_text,
       r.state, r.ansp_version, r.created_by, r.activated_by, r.ended_by, r.cancelled_by,
       r.created_at, r.activated_at, r.ended_at_actual, r.request_id, r.published_version,
       r.dss_constraint_id, r.dss_version, r.supersedes_id, r.activate_at, r.cis_version,
       v.feature, v."constraint", r.dss_state, r.dss_pending_since, r.dss_reference, r.dss_put_version
FROM restrictions r
JOIN restriction_versions v ON v.restriction_id = r.id AND v.version = r.ansp_version
WHERE (sqlc.narg(state)::restriction_state IS NULL OR r.state = sqlc.narg(state)::restriction_state)
  AND (sqlc.narg(at)::timestamptz IS NULL OR (r.starts_at <= sqlc.narg(at)::timestamptz AND r.ends_at > sqlc.narg(at)::timestamptz))
  AND (sqlc.narg(west)::float8 IS NULL OR
       ST_Intersects(CASE WHEN r.radius_m IS NULL THEN r.geom ELSE ST_Buffer(r.geom::geography, r.radius_m)::geometry END,
       CASE WHEN sqlc.narg(west)::float8 <= sqlc.narg(east)::float8
                THEN ST_MakeEnvelope(sqlc.narg(west)::float8, sqlc.narg(south)::float8, sqlc.narg(east)::float8, sqlc.narg(north)::float8, 4326)
                ELSE ST_Collect(ST_MakeEnvelope(sqlc.narg(west)::float8, sqlc.narg(south)::float8, 180, sqlc.narg(north)::float8, 4326),
                                ST_MakeEnvelope(-180, sqlc.narg(south)::float8, sqlc.narg(east)::float8, sqlc.narg(north)::float8, 4326))
       END))
ORDER BY r.created_at DESC, r.id DESC
LIMIT sqlc.arg(page_size);

-- name: DueActivations :many
SELECT id FROM restrictions
WHERE state = 'planned' AND activate_at IS NOT NULL AND activate_at <= clock_timestamp()
ORDER BY activate_at
LIMIT sqlc.arg(page_size);

-- name: DueExpiries :many
SELECT id FROM restrictions
WHERE state = 'active' AND ends_at <= clock_timestamp()
ORDER BY ends_at
LIMIT sqlc.arg(page_size);

-- name: RestrictionSuccessor :many
SELECT id FROM restrictions
WHERE supersedes_id = sqlc.arg(id) AND state = 'planned'
ORDER BY starts_at
LIMIT 1;

-- name: UnpublishedVersions :many
SELECT v.restriction_id, v.version, v.feature, v."constraint", v.changed_by, v.changed_at, v.change_reason,
       v.state, v.starts_at, v.ends_at, v.msg_id, r.ansp_ref
FROM restrictions r
JOIN restriction_versions v ON v.restriction_id = r.id AND v.version > r.bus_version
WHERE r.bus_version < r.ansp_version
ORDER BY v.changed_at, v.restriction_id, v.version
LIMIT sqlc.arg(page_size);

-- name: MarkBusPublished :exec
UPDATE restrictions SET bus_version = GREATEST(bus_version, sqlc.arg(version)::bigint)
WHERE id = sqlc.arg(id) AND sqlc.arg(version)::bigint <= ansp_version;

-- name: RestrictionVersion :one
-- constraint carries the reference the DSS accepted for this version
-- (WP-9), when it did.
SELECT v.restriction_id, v.version, v.feature,
       (CASE WHEN w.reference IS NULL THEN v."constraint"
             ELSE COALESCE(v."constraint", '{}'::jsonb) || jsonb_build_object('reference', w.reference) END)::jsonb AS "constraint",
       v.changed_by, v.changed_at, v.change_reason, v.state, v.starts_at, v.ends_at, v.msg_id, r.ansp_ref
FROM restriction_versions v JOIN restrictions r ON r.id = v.restriction_id
LEFT JOIN dss_constraint_writes w ON w.restriction_id = v.restriction_id AND w.ansp_version = v.version AND w.op = 'put'
WHERE v.restriction_id = sqlc.arg(restriction_id) AND v.version = sqlc.arg(version);

-- name: RestrictionAreaM2 :one
SELECT ST_Area(
    CASE WHEN sqlc.narg(radius_m)::float8 IS NULL
         THEN ST_SetSRID(ST_GeomFromGeoJSON(sqlc.arg(geom_geojson)::text), 4326)::geography
         ELSE ST_Buffer(ST_SetSRID(ST_GeomFromGeoJSON(sqlc.arg(geom_geojson)::text), 4326)::geography, sqlc.narg(radius_m)::float8)
    END)::float8 AS area_m2;

-- name: RelateShapes :one
-- a is the restriction, b the airspace part; a circle is its geodesic
-- buffer. intersects on geography; covers on the planar outline in
-- degrees (PostGIS has no geography ST_Covers for two polygons): the
-- shapes are tens of kilometres at most, where the two agree to metres.
WITH s AS (
    SELECT
        CASE WHEN sqlc.narg(a_radius_m)::float8 IS NULL
             THEN ST_SetSRID(ST_GeomFromGeoJSON(sqlc.arg(a_geojson)::text), 4326)
             ELSE ST_Buffer(ST_SetSRID(ST_GeomFromGeoJSON(sqlc.arg(a_geojson)::text), 4326)::geography, sqlc.narg(a_radius_m)::float8)::geometry
        END AS a,
        CASE WHEN sqlc.narg(b_radius_m)::float8 IS NULL
             THEN ST_SetSRID(ST_GeomFromGeoJSON(sqlc.arg(b_geojson)::text), 4326)
             ELSE ST_Buffer(ST_SetSRID(ST_GeomFromGeoJSON(sqlc.arg(b_geojson)::text), 4326)::geography, sqlc.narg(b_radius_m)::float8)::geometry
        END AS b
)
SELECT ST_Intersects(a::geography, b::geography)::boolean AS intersects,
       ST_Covers(b, a)::boolean AS covers
FROM s;

-- name: RestrictionRequestByClientRef :one
SELECT * FROM restriction_requests WHERE requester = sqlc.arg(requester) AND client_ref = sqlc.arg(client_ref);

-- name: CountOpenRestrictionRequests :one
SELECT count(*)::bigint AS n FROM restriction_requests WHERE requester = sqlc.arg(requester) AND state = 'received';

-- name: LockRestrictionRequest :one
SELECT * FROM restriction_requests WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: DecideRestrictionRequest :execrows
UPDATE restriction_requests SET
    state = sqlc.arg(state), decided_by = sqlc.arg(decided_by), decided_at = sqlc.arg(decided_at),
    decision_reason = sqlc.narg(decision_reason), restriction_id = sqlc.narg(restriction_id)
WHERE id = sqlc.arg(id) AND state = 'received';
