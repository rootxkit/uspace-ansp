-- docs/PLAN.md section 15 gap 3, D3: a dynamic restriction's limits may
-- be AGL (ED-318 CodeVerticalReferenceType), as the U-space airspaces
-- they modify usually are. lower_ref and upper_ref admit AGL beside AMSL
-- and WGS84; the value stays what the supervisor gave, never converted
-- in the row (03 conventions: no stored AGL derived from AMSL, and no
-- AMSL derived from AGL either). The absolute altitudes are derived
-- where they are needed, in internal/restriction, from the DEM and the
-- geoid, and recorded in restriction_versions.constraint.derivation.
--
-- The Down migration refuses while an AGL restriction exists rather than
-- rewriting or deleting it: a restriction is never lost to a rollback.

-- +goose Up
ALTER TABLE restrictions
    DROP CONSTRAINT restrictions_lower_ref_check,
    DROP CONSTRAINT restrictions_upper_ref_check,
    ADD CONSTRAINT restrictions_lower_ref_check CHECK (lower_ref IN ('AGL', 'AMSL', 'WGS84')),
    ADD CONSTRAINT restrictions_upper_ref_check CHECK (upper_ref IN ('AGL', 'AMSL', 'WGS84'));

-- +goose Down
ALTER TABLE restrictions
    DROP CONSTRAINT restrictions_lower_ref_check,
    DROP CONSTRAINT restrictions_upper_ref_check,
    ADD CONSTRAINT restrictions_lower_ref_check CHECK (lower_ref IN ('AMSL', 'WGS84')),
    ADD CONSTRAINT restrictions_upper_ref_check CHECK (upper_ref IN ('AMSL', 'WGS84'));
