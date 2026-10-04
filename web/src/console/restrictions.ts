// The restriction list as the console holds it: GET /v1/restrictions,
// then every restriction/state/v1 frame of the stream on top (the body
// of a state change or of a delivery outcome, api/openapi.yaml
// RestrictionStateBody). Copying, not judging: a frame replaces what it
// carries and nothing else, an older version never replaces a newer one,
// and a restriction the list does not hold asks for a reload of the list
// (the REST answer carries what a frame does not: the area, the limits,
// who did what).
import type { ConsoleFrame } from "@rootxkit/uspace-ui/live";
import type { components } from "../api/types";
import type { ApiAlarm, ApiRestriction } from "./delivery";

export type ApiStateBody = components["schemas"]["RestrictionStateBody"];

/** The schema of a restriction frame on the stream. */
export const RESTRICTION_STATE_SCHEMA = "restriction/state/v1";

const STATES = new Set(["planned", "active", "ended", "cancelled"]);

function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/**
 * The body of a restriction/state/v1 frame, or null when the frame is
 * another schema or lacks a member the merge reads (counted by the
 * caller as ignored, never applied in part).
 */
export function stateBodyOf(frame: ConsoleFrame): ApiStateBody | null {
  if (frame.schema !== RESTRICTION_STATE_SCHEMA) return null;
  const b = obj(frame.body);
  if (b === null) return null;
  if (typeof b["restriction_id"] !== "string" || typeof b["state"] !== "string" || !STATES.has(b["state"])) return null;
  if (typeof b["ansp_version"] !== "number" || !Number.isInteger(b["ansp_version"])) return null;
  if (typeof b["starts_at"] !== "string" || typeof b["ends_at"] !== "string" || obj(b["feature"]) === null) return null;
  return b as unknown as ApiStateBody;
}

export interface Merged {
  restrictions: ApiRestriction[];
  /** The frame named a restriction the list does not hold: reload the list. */
  unknown: boolean;
  /** The frame was older than what the list holds and was not applied. */
  stale: boolean;
}

/** `body` applied to `list`; `list` itself is not changed. */
export function mergeState(list: readonly ApiRestriction[], body: ApiStateBody): Merged {
  const i = list.findIndex((r) => r.id === body.restriction_id);
  if (i < 0) return { restrictions: [...list], unknown: true, stale: false };
  const cur = list[i] as ApiRestriction;
  if (body.ansp_version < cur.ansp_version) return { restrictions: [...list], unknown: false, stale: true };
  const next: ApiRestriction = {
    ...cur,
    state: body.state,
    starts_at: body.starts_at,
    ends_at: body.ends_at,
    ansp_version: body.ansp_version,
    feature: body.feature,
    ...(body.deliveries === undefined ? {} : { deliveries: body.deliveries }),
    ...(body.dss === undefined ? {} : { dss: body.dss }),
    ...(body.published === true ? { published_version: body.ansp_version } : {}),
  };
  const out = [...list];
  out[i] = next;
  return { restrictions: out, unknown: false, stale: false };
}

/** The alarm a frame carries, merged into `alarms` by id (newest state wins). */
export function mergeAlarm(alarms: readonly ApiAlarm[], alarm: ApiAlarm | undefined): ApiAlarm[] {
  if (alarm === undefined) return [...alarms];
  const out = alarms.filter((a) => a.id !== alarm.id);
  return [alarm, ...out];
}

/**
 * Whether a frame naming a restriction the list does not hold asks for
 * a reload of a list filtered to `filter` (null: every state). A frame in
 * a state the filter leaves out does not: the reload would not hold that
 * restriction either, and every such frame would read the list again.
 */
export function reloadsFor(body: ApiStateBody, filter: string | null): boolean {
  return filter === null || body.state === filter;
}
