// The thresholds row (ansp_policy, INV-03; api/openapi.yaml Policy and
// PolicyUpdate) as the policy page shows and edits it. The unit of each
// threshold is the one its name states (E-13: _m metres, _s seconds);
// the page reads what is typed as numbers and sends them, and the API
// refuses what is not finite and positive with its field problems. No
// value here is a default: the form starts from the API's current row.
import type { components } from "../api/types";

export type ApiPolicy = components["schemas"]["Policy"];
export type ApiPolicyUpdate = components["schemas"]["PolicyUpdate"];

/** The numeric thresholds, in the contract's order. */
export const THRESHOLDS = [
  "feed_margin_lateral_m",
  "feed_margin_vertical_m",
  "stale_after_s",
  "source_liveness_s",
  "cisp_alarm_after_s",
  "cisp_heartbeat_s",
  "cis_reconcile_s",
  "cis_stale_bound_s",
  "notice_escalation_s",
] as const satisfies readonly (keyof ApiPolicyUpdate)[];

export type Threshold = (typeof THRESHOLDS)[number];

export const ZONE_TYPES = ["PROHIBITED", "REQ_AUTHORIZATION"] as const;

/** The unit a threshold's name states. */
export function unitOf(name: Threshold): "m" | "s" {
  return name.endsWith("_m") ? "m" : "s";
}

/** The form: every member as typed. */
export type PolicyForm = Record<Threshold, string> & { default_zone_type: string; country: string };

/** The form holding the API's row. */
export function formOf(p: ApiPolicyUpdate): PolicyForm {
  const out = { default_zone_type: p.default_zone_type, country: p.country } as PolicyForm;
  for (const k of THRESHOLDS) out[k] = String(p[k]);
  return out;
}

/** A shape error of the form, before anything is sent. */
export interface FormProblem {
  field: string;
  problem: "number" | "positive" | "zone_type" | "country";
}

const COUNTRY = /^[A-Z]{3}$/;

/**
 * The PUT /v1/policy body of the form, or the members that are not the
 * shape the contract takes (a number, finite and above zero; a zone type
 * of the enumeration; three capital letters). Meaning is the API's.
 */
export function policyBody(f: PolicyForm): { body: ApiPolicyUpdate } | { problems: FormProblem[] } {
  const problems: FormProblem[] = [];
  const numbers: Partial<Record<Threshold, number>> = {};
  for (const k of THRESHOLDS) {
    const raw = f[k].trim();
    const n = raw === "" ? Number.NaN : Number(raw);
    if (!Number.isFinite(n)) problems.push({ field: k, problem: "number" });
    else if (n <= 0) problems.push({ field: k, problem: "positive" });
    else numbers[k] = n;
  }
  if (!(ZONE_TYPES as readonly string[]).includes(f.default_zone_type)) problems.push({ field: "default_zone_type", problem: "zone_type" });
  const country = f.country.trim();
  if (!COUNTRY.test(country)) problems.push({ field: "country", problem: "country" });
  if (problems.length > 0) return { problems };
  return {
    body: {
      ...(numbers as Record<Threshold, number>),
      default_zone_type: f.default_zone_type as ApiPolicyUpdate["default_zone_type"],
      country,
    },
  };
}

/** The thresholds a change moves: name, value before, value after. */
export function changes(before: ApiPolicyUpdate, after: ApiPolicyUpdate): { field: string; from: string; to: string }[] {
  const out: { field: string; from: string; to: string }[] = [];
  for (const k of [...THRESHOLDS, "default_zone_type", "country"] as const) {
    if (String(before[k]) !== String(after[k])) out.push({ field: k, from: String(before[k]), to: String(after[k]) });
  }
  return out;
}

/** The audit entity of one policy version (store.EntityPolicy, entity id the version). */
export function policyAuditEntity(version: number): string {
  return `ansp_policy:${version}`;
}

/** How many versions the history reads back, newest first. A display bound. */
export const HISTORY_VERSIONS = 10;

/** The versions the history reads: the current one and up to HISTORY_VERSIONS - 1 before it. */
export function historyVersions(current: number): number[] {
  const out: number[] = [];
  for (let v = current; v >= 1 && out.length < HISTORY_VERSIONS; v--) out.push(v);
  return out;
}
