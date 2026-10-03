// An adapter's state in words (LESSONS B-11: disabled is not silent). The
// API states the status (configured: never heard; running; silent: no
// status within source_liveness_s; disabled: by a source switch); the
// switch that disabled it, with who, when and why, is the matching row of
// GET /v1/sources: the adapter's own instance first, then the whole
// `manned` type (instance "*", cmd/api/sources.go). Nothing is judged
// here, and nothing is called "lost" (C-12).
import type { components } from "../api/types";

export type ApiAdapter = components["schemas"]["Adapter"];
export type ApiSourceControl = components["schemas"]["SourceControl"];

/** The whole-type switch's instance (cmd/api/sources.go). */
export const TYPE_INSTANCE = "*";

/** The switch that governs `adapter`: its own, else the type's; null when there is none. */
export function switchFor(adapter: Pick<ApiAdapter, "id">, controls: readonly ApiSourceControl[]): ApiSourceControl | null {
  const own = controls.find((c) => c.source_type === "manned" && c.instance_id === adapter.id);
  if (own !== undefined) return own;
  return controls.find((c) => c.source_type === "manned" && c.instance_id === TYPE_INSTANCE) ?? null;
}

export interface StatusLine {
  key: string;
  vars: Record<string, string | number>;
  attention: boolean;
}

/** The line under an adapter's name. */
export function statusLine(a: ApiAdapter, control: ApiSourceControl | null): StatusLine {
  const lastFrame = a.last_frame_at ?? "";
  switch (a.status) {
    case "configured":
      return { key: "ansp.adapters.status.configured", vars: {}, attention: false };
    case "running":
      return { key: "ansp.adapters.status.running", vars: { at: lastFrame }, attention: false };
    case "silent":
      return {
        key: lastFrame === "" ? "ansp.adapters.status.silent_never" : "ansp.adapters.status.silent",
        vars: { since: lastFrame, status_at: a.last_status_at ?? "" },
        attention: true,
      };
    case "disabled":
      if (control === null || control.enabled) return { key: "ansp.adapters.status.disabled_unknown", vars: {}, attention: true };
      return {
        key: control.instance_id === TYPE_INSTANCE ? "ansp.adapters.status.disabled_type" : "ansp.adapters.status.disabled",
        vars: { actor: control.actor, at: control.changed_at, reason: control.reason },
        attention: true,
      };
  }
}
