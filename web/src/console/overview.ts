// The overview's figures, counted from what the console already reads
// (GET /v1/restrictions, /v1/delivery-alarms, /v1/adapters, /v1/sources
// and the coordination inbox). Counting only: every state is the API's,
// nothing is judged or thresholded here.
import type { ApiAdapter, ApiSourceControl } from "./adapters";
import type { ApiAlarm, ApiRestriction } from "./delivery";

export interface RestrictionCounts {
  active: number;
  planned: number;
  ended: number;
  cancelled: number;
}

/** The restrictions of a list by state. */
export function restrictionCounts(list: readonly Pick<ApiRestriction, "state">[]): RestrictionCounts {
  const c: RestrictionCounts = { active: 0, planned: 0, ended: 0, cancelled: 0 };
  for (const r of list) {
    if (r.state in c) c[r.state as keyof RestrictionCounts] += 1;
  }
  return c;
}

/** The alarms the API has not cleared, oldest first (an alarm stays until the API clears it). */
export function openAlarms(alarms: readonly ApiAlarm[]): ApiAlarm[] {
  return alarms.filter((a) => a.state !== "cleared").sort((a, b) => a.since.localeCompare(b.since));
}

export interface AdapterCounts {
  running: number;
  silent: number;
  disabled: number;
  configured: number;
  total: number;
}

/** The adapters by the status the API states. */
export function adapterCounts(adapters: readonly Pick<ApiAdapter, "status">[]): AdapterCounts {
  const c: AdapterCounts = { running: 0, silent: 0, disabled: 0, configured: 0, total: adapters.length };
  for (const a of adapters) c[a.status] += 1;
  return c;
}

/** The source switches that are off (each says who, when and why on the switches page). */
export function switchesOff(controls: readonly Pick<ApiSourceControl, "enabled">[]): number {
  return controls.filter((c) => !c.enabled).length;
}

/** The newest restrictions first, by when they were planned, at most `n`. */
export function recentRestrictions(list: readonly ApiRestriction[], n: number): ApiRestriction[] {
  return [...list].sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, n);
}
