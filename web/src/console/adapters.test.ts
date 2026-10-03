// An adapter's line: disabled (by whom, why) is not silent (B-11), and
// each state has its words.
import { describe, expect, it } from "vitest";
import { statusLine, switchFor, type ApiAdapter, type ApiSourceControl } from "./adapters";

function adapter(over: Partial<ApiAdapter> = {}): ApiAdapter {
  return {
    id: "replay-1",
    kind: "replay",
    display_name: "Replay (synthetic)",
    source_class: "ads_b",
    status: "running",
    enabled: true,
    last_frame_at: "2026-10-02T12:00:00.000Z",
    last_status_at: "2026-10-02T12:00:01.000Z",
    counters: { accepted: 10, refused: 0 },
    ...over,
  };
}

function control(over: Partial<ApiSourceControl> = {}): ApiSourceControl {
  return {
    source_type: "manned",
    instance_id: "replay-1",
    enabled: false,
    reason: "Feed under maintenance (synthetic)",
    actor: "admin",
    changed_at: "2026-10-02T11:00:00.000Z",
    version: 3,
    epoch: "4f5a2b1c-0000-4000-8000-000000000000",
    ...over,
  };
}

describe("the switch of an adapter", () => {
  it("is its own before the whole type", () => {
    const own = control();
    const type = control({ instance_id: "*", reason: "all manned off" });
    expect(switchFor(adapter(), [type, own])).toBe(own);
    expect(switchFor(adapter(), [type])).toBe(type);
    expect(switchFor(adapter(), [control({ instance_id: "other" })])).toBeNull();
  });
});

describe("the status line", () => {
  it("says running with the last frame", () => {
    expect(statusLine(adapter(), null)).toEqual({
      key: "ansp.adapters.status.running",
      vars: { at: "2026-10-02T12:00:00.000Z" },
      attention: false,
    });
  });

  it("says configured, never heard", () => {
    expect(statusLine(adapter({ status: "configured", last_frame_at: null }), null).key).toBe("ansp.adapters.status.configured");
  });

  it("says silent since the last frame, and silent without any", () => {
    expect(statusLine(adapter({ status: "silent" }), null)).toMatchObject({ key: "ansp.adapters.status.silent", attention: true });
    expect(statusLine(adapter({ status: "silent", last_frame_at: null }), null).key).toBe("ansp.adapters.status.silent_never");
  });

  it("says disabled by whom, when and why, unlike silent", () => {
    const l = statusLine(adapter({ status: "disabled", enabled: false }), control());
    expect(l).toEqual({
      key: "ansp.adapters.status.disabled",
      vars: { actor: "admin", at: "2026-10-02T11:00:00.000Z", reason: "Feed under maintenance (synthetic)" },
      attention: true,
    });
    expect(l.key).not.toBe(statusLine(adapter({ status: "silent" }), null).key);
  });

  it("says a whole-type switch, and a disabled adapter whose switch is not listed", () => {
    expect(statusLine(adapter({ status: "disabled" }), control({ instance_id: "*" })).key).toBe("ansp.adapters.status.disabled_type");
    expect(statusLine(adapter({ status: "disabled" }), null).key).toBe("ansp.adapters.status.disabled_unknown");
    expect(statusLine(adapter({ status: "disabled" }), control({ enabled: true })).key).toBe("ansp.adapters.status.disabled_unknown");
  });
});
