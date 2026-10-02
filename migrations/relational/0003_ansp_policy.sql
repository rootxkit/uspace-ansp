-- ansp_policy: the thresholds every judgement of this system runs with
-- (INV-03, docs/PLAN.md section 5.1). A version is never edited: a
-- change is a new row with the next policy_version from
-- ansp_policy_version_seq, and the newest row is the policy. ansp_app
-- may SELECT and INSERT only, and nothing references the table.
-- internal/policy.Defaults holds the same defaults and an integration
-- test compares the two.
--
-- Every threshold is finite and positive: the CHECK refuses zero,
-- negative, NaN and infinity ('NaN' sorts above 'Infinity' in
-- PostgreSQL, so "< 'Infinity'" refuses both).

-- +goose Up
CREATE SEQUENCE ansp_policy_version_seq AS bigint MINVALUE 1;

CREATE TABLE ansp_policy (
    policy_version         bigint           PRIMARY KEY DEFAULT nextval('ansp_policy_version_seq') CHECK (policy_version >= 1),
    feed_margin_lateral_m  double precision NOT NULL DEFAULT 5000,
    feed_margin_vertical_m double precision NOT NULL DEFAULT 1500,
    stale_after_s          double precision NOT NULL DEFAULT 15,
    source_liveness_s      double precision NOT NULL DEFAULT 15,
    cisp_alarm_after_s     double precision NOT NULL DEFAULT 10,
    cisp_heartbeat_s       double precision NOT NULL DEFAULT 15,
    cis_reconcile_s        double precision NOT NULL DEFAULT 60,
    cis_stale_bound_s      double precision NOT NULL DEFAULT 300,
    notice_escalation_s    double precision NOT NULL DEFAULT 60,
    default_zone_type      text             NOT NULL DEFAULT 'PROHIBITED'
                           CHECK (default_zone_type IN ('PROHIBITED', 'REQ_AUTHORIZATION')),
    country                text             NOT NULL DEFAULT 'GEO' CHECK (country ~ '^[A-Z]{3}$'),
    changed_by             text             NOT NULL CHECK (changed_by <> ''),
    changed_at             timestamptz      NOT NULL DEFAULT now(),
    CONSTRAINT ansp_policy_finite_positive CHECK (
        feed_margin_lateral_m  > 0 AND feed_margin_lateral_m  < 'Infinity' AND
        feed_margin_vertical_m > 0 AND feed_margin_vertical_m < 'Infinity' AND
        stale_after_s          > 0 AND stale_after_s          < 'Infinity' AND
        source_liveness_s      > 0 AND source_liveness_s      < 'Infinity' AND
        cisp_alarm_after_s     > 0 AND cisp_alarm_after_s     < 'Infinity' AND
        cisp_heartbeat_s       > 0 AND cisp_heartbeat_s       < 'Infinity' AND
        cis_reconcile_s        > 0 AND cis_reconcile_s        < 'Infinity' AND
        cis_stale_bound_s      > 0 AND cis_stale_bound_s      < 'Infinity' AND
        notice_escalation_s    > 0 AND notice_escalation_s    < 'Infinity'
    )
);

ALTER SEQUENCE ansp_policy_version_seq OWNED BY ansp_policy.policy_version;

-- Version 1: the documented defaults.
INSERT INTO ansp_policy (changed_by) VALUES ('migration');

GRANT SELECT, INSERT ON ansp_policy TO ansp_app;
GRANT USAGE, SELECT ON SEQUENCE ansp_policy_version_seq TO ansp_app;

-- +goose Down
DROP TABLE IF EXISTS ansp_policy;
DROP SEQUENCE IF EXISTS ansp_policy_version_seq;
