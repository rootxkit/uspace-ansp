// The occurrence report form (Reg. (EU) 376/2014 Art. 4(8); 01 N4;
// api/openapi.yaml OccurrenceCreate, the 04 §3.3 occurrence/v1 field
// list until the authority publishes the schema, docs/PLAN.md section 15
// row 23) and the body it becomes. Shape only: the API judges the
// meaning and answers its field problems. The reporter reference is a
// protected value: it goes in the body and nowhere else (never logged,
// shown back, stored in the browser or exported).
//
// POST /v1/occurrences takes no idempotency key (docs/PLAN.md section 15
// row 52): a report that got no answer may have been queued, so it is
// never sent again by itself; the supervisor is told the outcome is
// unknown and must say so to send it again (outcomeAfter).
import type { components } from "../api/types";
import type { CallFailure } from "../api/client";

export type ApiOccurrenceCreate = components["schemas"]["OccurrenceCreate"];
export type ApiOccurrenceQueued = components["schemas"]["OccurrenceQueued"];

export const CHANNELS = ["mandatory", "voluntary"] as const;
export const CATEGORIES = ["airprox", "nonconformance_in_prohibited", "lost_link_in_uspace", "emergency", "other"] as const;

/** The bounds the contract states (OccurrenceCreate). */
export const LIST_MAX = 50;
export const NARRATIVE_MAX_CHARS = 10_000;
export const REPORTER_REF_MAX_CHARS = 128;

/**
 * The reporting deadline after the reporter became aware: 72 h, a
 * regulation (376/2014 Art. 4(8); coord.OccurrenceDeadline), not a
 * threshold. Shown before sending; the API's deadline_at is the record.
 */
export const DEADLINE_H = 72;

export interface AircraftRow {
  serial: string;
  operator_reg: string;
  flight_id: string;
  authorisation_number: string;
}

export interface MannedRow {
  icao24: string;
  callsign: string;
}

export interface OccurrenceForm {
  channel: string;
  occurred_at: string | null;
  became_aware_at: string | null;
  category: string;
  aircraft: AircraftRow[];
  manned: MannedRow[];
  intent_refs: string;
  min_h_m: string;
  min_v_m: string;
  min_at: string | null;
  narrative: string;
  reporter_person_ref: string;
}

export function emptyForm(): OccurrenceForm {
  return {
    channel: "mandatory",
    occurred_at: null,
    became_aware_at: null,
    category: "airprox",
    aircraft: [],
    manned: [],
    intent_refs: "",
    min_h_m: "",
    min_v_m: "",
    min_at: null,
    narrative: "",
    reporter_person_ref: "",
  };
}

export interface FormProblem {
  field: string;
  problem: "required" | "enum" | "icao24" | "uuid" | "number" | "too_many" | "too_long";
}

const ICAO24 = /^[0-9a-f]{6}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function nonNegative(raw: string): number | null | undefined {
  const s = raw.trim();
  if (s === "") return null;
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

/** The OccurrenceCreate body of the form, or what keeps it from being sent. */
export function occurrenceBody(f: OccurrenceForm): { body: ApiOccurrenceCreate } | { problems: FormProblem[] } {
  const problems: FormProblem[] = [];
  if (!(CHANNELS as readonly string[]).includes(f.channel)) problems.push({ field: "channel", problem: "enum" });
  if (!(CATEGORIES as readonly string[]).includes(f.category)) problems.push({ field: "category", problem: "enum" });
  if (f.occurred_at === null) problems.push({ field: "occurred_at", problem: "required" });
  if (f.became_aware_at === null) problems.push({ field: "became_aware_at", problem: "required" });
  const narrative = f.narrative.trim();
  if (narrative === "") problems.push({ field: "narrative", problem: "required" });
  else if (narrative.length > NARRATIVE_MAX_CHARS) problems.push({ field: "narrative", problem: "too_long" });
  const ref = f.reporter_person_ref.trim();
  if (ref.length > REPORTER_REF_MAX_CHARS) problems.push({ field: "reporter_person_ref", problem: "too_long" });

  const aircraft = f.aircraft
    .map((a) => ({ serial: a.serial.trim(), operator_reg: a.operator_reg.trim(), flight_id: a.flight_id.trim(), authorisation_number: a.authorisation_number.trim() }))
    .filter((a) => Object.values(a).some((v) => v !== ""))
    .map((a) => Object.fromEntries(Object.entries(a).filter(([, v]) => v !== "")) as Partial<AircraftRow>);
  if (aircraft.length > LIST_MAX) problems.push({ field: "aircraft", problem: "too_many" });

  const manned = f.manned
    .map((m) => ({ icao24: m.icao24.trim().toLowerCase(), callsign: m.callsign.trim() }))
    .filter((m) => m.icao24 !== "" || m.callsign !== "");
  manned.forEach((m, i) => {
    if (m.icao24 !== "" && !ICAO24.test(m.icao24)) problems.push({ field: `manned[${i}].icao24`, problem: "icao24" });
  });
  if (manned.length > LIST_MAX) problems.push({ field: "manned", problem: "too_many" });

  const refs = f.intent_refs
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s !== "");
  refs.forEach((r, i) => {
    if (!UUID.test(r)) problems.push({ field: `intent_refs[${i}]`, problem: "uuid" });
  });
  if (refs.length > LIST_MAX) problems.push({ field: "intent_refs", problem: "too_many" });

  const h = nonNegative(f.min_h_m);
  const v = nonNegative(f.min_v_m);
  if (h === undefined) problems.push({ field: "min_separation.h_m", problem: "number" });
  if (v === undefined) problems.push({ field: "min_separation.v_m", problem: "number" });

  if (problems.length > 0 || f.occurred_at === null || f.became_aware_at === null) return { problems };
  const min = {
    ...(h === null || h === undefined ? {} : { h_m: h }),
    ...(v === null || v === undefined ? {} : { v_m: v }),
    ...(f.min_at === null ? {} : { at: f.min_at }),
  };
  return {
    body: {
      channel: f.channel as ApiOccurrenceCreate["channel"],
      occurred_at: f.occurred_at,
      became_aware_at: f.became_aware_at,
      category: f.category as ApiOccurrenceCreate["category"],
      narrative,
      ...(aircraft.length === 0 ? {} : { aircraft }),
      ...(manned.length === 0 ? {} : { manned: manned.map((m) => (m.callsign === "" ? { icao24: m.icao24 } : m.icao24 === "" ? { callsign: m.callsign } : m)) }),
      ...(refs.length === 0 ? {} : { intent_refs: refs.map((r) => r.toLowerCase()) }),
      ...(Object.keys(min).length === 0 ? {} : { min_separation: min }),
      ...(ref === "" ? {} : { reporter_person_ref: ref }),
    },
  };
}

/** The deadline 376/2014 sets after `becameAwareAt`, for the form to show; null without a time. */
export function deadlinePreview(becameAwareAt: string | null): string | null {
  if (becameAwareAt === null) return null;
  const ms = Date.parse(becameAwareAt);
  return Number.isFinite(ms) ? new Date(ms + DEADLINE_H * 3_600_000).toISOString() : null;
}

/**
 * What a failed send means for the next one: "refused" (the API answered
 * with a problem; nothing was queued, the form can be corrected and
 * sent), or "unknown" (no answer, the BFF's 502 or 504: it may have been
 * queued, so a second send needs the supervisor's explicit say-so).
 */
export function outcomeAfter(f: CallFailure): "refused" | "unknown" {
  const answered = f.status >= 400 && f.problem !== null && f.status !== 502 && f.status !== 504;
  return answered ? "refused" : "unknown";
}
