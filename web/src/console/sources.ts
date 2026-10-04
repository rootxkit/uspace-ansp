// The source switches as the sources page lists them (04 §3.6, U-15,
// LESSONS B-09, B-11): the whole manned type (instance "*",
// cmd/api/sources.go) first, then every adapter the API registers, then
// any switch of an instance the registry no longer holds. Each row is the
// switch as GET /v1/sources states it (who, when, why, version) or "no
// switch set"; nothing here decides whether a source runs.
import type { ApiAdapter, ApiSourceControl } from "./adapters";
import { TYPE_INSTANCE } from "./adapters";

/** The one source type of this system (SourceControl.source_type). */
export const SOURCE_TYPE = "manned";

export interface SwitchRow {
  /** "*" for the type, else the adapter id. */
  instance: string;
  adapter: ApiAdapter | null;
  control: ApiSourceControl | null;
}

/** The rows of the page, in its order. */
export function switchRows(adapters: readonly ApiAdapter[], controls: readonly ApiSourceControl[]): SwitchRow[] {
  const own = (instance: string) => controls.find((c) => c.source_type === SOURCE_TYPE && c.instance_id === instance) ?? null;
  const rows: SwitchRow[] = [{ instance: TYPE_INSTANCE, adapter: null, control: own(TYPE_INSTANCE) }];
  const ids = new Set<string>();
  for (const a of [...adapters].sort((x, y) => x.id.localeCompare(y.id))) {
    ids.add(a.id);
    rows.push({ instance: a.id, adapter: a, control: own(a.id) });
  }
  for (const c of controls) {
    if (c.source_type !== SOURCE_TYPE || c.instance_id === TYPE_INSTANCE || ids.has(c.instance_id)) continue;
    ids.add(c.instance_id);
    rows.push({ instance: c.instance_id, adapter: null, control: c });
  }
  return rows;
}

/** Whether the row's switch is on: a row with no switch set is enabled. */
export function isEnabled(row: Pick<SwitchRow, "control">): boolean {
  return row.control === null || row.control.enabled;
}

/** The PUT /v1/sources/{type}/{instance} body (SourceControlUpdate). */
export function switchBody(enabled: boolean, reason: string): { enabled: boolean; reason: string } {
  return { enabled, reason: reason.trim() };
}

/** The audit entity of a switch (store.EntitySourceControl, entity id "<type>/<instance>"). */
export function switchAuditEntity(instance: string): string {
  return `source_control:${SOURCE_TYPE}/${instance}`;
}
