import { describe, expect, it } from "vitest";
import { alarm, restriction } from "../../test/fixtures";
import { adapterCounts, openAlarms, recentRestrictions, restrictionCounts, switchesOff } from "./overview";

describe("overview figures", () => {
  it("counts restrictions by state, and an empty list as zeros", () => {
    expect(restrictionCounts([])).toEqual({ active: 0, planned: 0, ended: 0, cancelled: 0 });
    const list = [restriction({ state: "active" }), restriction({ state: "active" }), restriction({ state: "planned" }), restriction({ state: "cancelled" })];
    expect(restrictionCounts(list)).toEqual({ active: 2, planned: 1, ended: 0, cancelled: 1 });
  });

  it("keeps every alarm the API has not cleared, oldest first, and drops a cleared one", () => {
    const older = alarm({ id: "a1", since: "2026-10-02T11:00:00.000Z", state: "acknowledged" });
    const newer = alarm({ id: "a2", since: "2026-10-02T12:00:00.000Z" });
    const cleared = alarm({ id: "a3", state: "cleared" });
    expect(openAlarms([newer, cleared, older]).map((a) => a.id)).toEqual(["a1", "a2"]);
    expect(openAlarms([cleared])).toEqual([]);
  });

  it("counts adapters by the API's status", () => {
    expect(adapterCounts([])).toEqual({ running: 0, silent: 0, disabled: 0, configured: 0, total: 0 });
    expect(adapterCounts([{ status: "running" }, { status: "silent" }, { status: "disabled" }, { status: "running" }])).toEqual({
      running: 2,
      silent: 1,
      disabled: 1,
      configured: 0,
      total: 4,
    });
  });

  it("counts the switches that are off, none when all are on", () => {
    expect(switchesOff([{ enabled: true }])).toBe(0);
    expect(switchesOff([{ enabled: true }, { enabled: false }])).toBe(1);
  });

  it("lists the newest restrictions first, at most n", () => {
    const a = restriction({ id: "A", created_at: "2026-10-02T10:00:00.000Z" });
    const b = restriction({ id: "B", created_at: "2026-10-02T12:00:00.000Z" });
    const c = restriction({ id: "C", created_at: "2026-10-02T11:00:00.000Z" });
    expect(recentRestrictions([a, b, c], 2).map((r) => r.id)).toEqual(["B", "C"]);
  });
});
