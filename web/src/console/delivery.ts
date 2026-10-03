// The words of a restriction's delivery state, per channel, as the API
// states it (docs/PLAN.md D5, D6; WP-8, WP-9): the CISP publication (the
// regulatory channel), the DSS constraint, the USS notifications and the
// degraded direct path. Nothing is judged here: every line is a field of
// the Restriction or of an open alarm, put into words. The wording never
// says "lost" for something that is queued, retried or unreachable
// (LESSONS C-12): "not yet published", "pending", "retrying".
import type { components } from "../api/types";

export type ApiRestriction = components["schemas"]["Restriction"];
export type ApiDeliveryChannel = components["schemas"]["DeliveryChannel"];
export type ApiAlarm = components["schemas"]["DeliveryAlarm"];
export type ApiDssStatus = components["schemas"]["DssStatus"];

/** One line of the delivery state: a catalogue key and its values. */
export interface Line {
  key: string;
  vars: Record<string, string | number>;
  /** An operator should look (a failure, an open alarm, a version not yet out). */
  attention: boolean;
}

/** The parts of a Restriction (or of a restriction/state/v1 body) the lines read. */
export interface DeliveryFacts {
  state: ApiRestriction["state"];
  ansp_version: number;
  published_version?: number | null;
  deliveries?: ApiRestriction["deliveries"];
  dss?: ApiDssStatus;
}

function channelVars(c: ApiDeliveryChannel): Record<string, string | number> {
  return {
    attempts: c.attempts,
    at: c.last_attempt_at ?? "",
    code: c.last_status_code ?? "",
    next: c.next_retry_at ?? "",
  };
}

/**
 * The CISP line. `alarm` is the open cisp_not_published alarm of this
 * restriction's current version, when there is one: its `since` is the
 * instant the version was due at the CISP.
 */
export function cispLine(r: DeliveryFacts, alarm: ApiAlarm | null): Line {
  const published = r.published_version ?? null;
  const c = r.deliveries?.cisp;
  if (published !== null && published >= r.ansp_version) {
    return {
      key: c?.last_attempt_at === undefined ? "ansp.delivery.cisp.published" : "ansp.delivery.cisp.published_at",
      vars: { version: published, at: c?.last_attempt_at ?? "" },
      attention: false,
    };
  }
  if (c !== undefined && c.state === "failed") {
    return { key: "ansp.delivery.cisp.failed", vars: { version: r.ansp_version, ...channelVars(c) }, attention: true };
  }
  if (c !== undefined && c.state === "abandoned") {
    return { key: "ansp.delivery.cisp.abandoned", vars: { version: r.ansp_version, ...channelVars(c) }, attention: true };
  }
  const since = alarm?.since ?? null;
  const vars: Record<string, string | number> = {
    version: r.ansp_version,
    since: since ?? "",
    published: published ?? "",
    attempts: c?.attempts ?? 0,
    next: c?.next_retry_at ?? "",
  };
  // A restriction no longer in force is not "awaiting" publication: its
  // last version stays what the CISP has.
  const over = r.state === "ended" || r.state === "cancelled";
  if (published !== null) {
    return {
      key: since === null ? "ansp.delivery.cisp.behind" : "ansp.delivery.cisp.behind_since",
      vars,
      attention: !over,
    };
  }
  return {
    key: since === null ? "ansp.delivery.cisp.not_yet" : "ansp.delivery.cisp.not_yet_since",
    vars,
    attention: alarm !== null || (c !== undefined && c.attempts > 0 && !over),
  };
}

/** The DSS line, from the DSS status (WP-9). */
export function dssLine(r: DeliveryFacts): Line {
  const d = r.dss;
  if (d === undefined) return { key: "ansp.delivery.dss.unknown", vars: {}, attention: false };
  const vars = {
    since: d.since ?? "",
    version: d.ansp_version ?? "",
    dss_version: d.dss_version ?? "",
  };
  switch (d.state) {
    case "none":
      return { key: "ansp.delivery.dss.none", vars, attention: false };
    case "pending":
      return { key: d.since === undefined ? "ansp.delivery.dss.pending" : "ansp.delivery.dss.pending_since", vars, attention: r.state === "active" };
    case "written":
      return { key: "ansp.delivery.dss.written", vars, attention: false };
    case "deleted":
      return { key: "ansp.delivery.dss.deleted", vars, attention: false };
    case "failed":
      return { key: "ansp.delivery.dss.failed", vars, attention: true };
  }
}

/** A further channel's line (USS notifications, the degraded direct path), or null when it has done nothing. */
export function channelLine(name: "uss_notify" | "direct_degraded", c: ApiDeliveryChannel | undefined): Line | null {
  if (c === undefined || c.state === "none") return null;
  return {
    key: `ansp.delivery.${name}.${c.state}`,
    vars: channelVars(c),
    attention: c.state === "failed" || c.state === "abandoned" || name === "direct_degraded",
  };
}

/** Every line of a restriction's delivery state, CISP first. */
export function deliveryLines(r: DeliveryFacts, alarms: readonly ApiAlarm[]): Line[] {
  const notPublished =
    alarms.find((a) => a.kind === "cisp_not_published" && a.state !== "cleared" && (a.ansp_version ?? r.ansp_version) === r.ansp_version) ??
    null;
  const out = [cispLine(r, notPublished), dssLine(r)];
  const uss = channelLine("uss_notify", r.deliveries?.uss_notify);
  if (uss !== null) out.push(uss);
  const direct = channelLine("direct_degraded", r.deliveries?.direct_degraded);
  if (direct !== null) out.push(direct);
  return out;
}

/** The alarms not cleared, of one restriction. */
export function openAlarmsOf(restrictionId: string, alarms: readonly ApiAlarm[]): ApiAlarm[] {
  return alarms.filter((a) => a.restriction_id === restrictionId && a.state !== "cleared");
}
