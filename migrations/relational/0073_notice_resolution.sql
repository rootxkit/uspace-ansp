-- WP-10: an ended notice resolves the deviation notices of its intents
-- (docs/PLAN.md section 15 row 6; 2021/664 Art. 13(2), Annex V).
--
-- A nonconformance or contingent notice escalates until a person
-- acknowledges it. When the same USSP (the same sender_client_id and
-- ussp_id) then sends an ended notice for its intents, the condition the
-- notice reported is over by the USSP's own word: resolved_at is when
-- the ended notice was received and resolved_by_ack_id names it, and the
-- notice escalates no more. It is not acknowledged by this: state stays
-- received, a person still sees it and files it, and a click never
-- closes a live condition. Only a notice that needs the acknowledgement
-- (ack_required) can be resolved; both columns are set together.

-- +goose Up
ALTER TABLE coordination_notices
    ADD COLUMN resolved_at        timestamptz,
    ADD COLUMN resolved_by_ack_id text REFERENCES coordination_notices (id),
    ADD CONSTRAINT coordination_notices_resolution_whole CHECK ((resolved_at IS NULL) = (resolved_by_ack_id IS NULL)),
    ADD CONSTRAINT coordination_notices_resolve_only_required CHECK (ack_required OR resolved_at IS NULL);

-- +goose Down
ALTER TABLE coordination_notices
    DROP CONSTRAINT coordination_notices_resolve_only_required,
    DROP CONSTRAINT coordination_notices_resolution_whole,
    DROP COLUMN resolved_by_ack_id,
    DROP COLUMN resolved_at;
