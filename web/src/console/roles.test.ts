import { describe, expect, it } from "vitest";
import { NAV_GROUPS, NAV_ITEMS, navFor, navItemOf } from "./roles";

describe("navigation", () => {
  it("files every item under a known group, the overview first", () => {
    expect(NAV_ITEMS[0]?.path).toBe("/overview");
    for (const i of NAV_ITEMS) expect(NAV_GROUPS).toContain(i.group);
  });

  it("links the admin pages for an admin only", () => {
    expect(navFor("admin").map((i) => i.path)).toEqual(expect.arrayContaining(["/policy", "/audit", "/users"]));
    for (const role of ["viewer", "watch_supervisor", null] as const) {
      expect(navFor(role).map((i) => i.path)).not.toContain("/policy");
      expect(navFor(role).map((i) => i.path)).not.toContain("/audit");
      expect(navFor(role).map((i) => i.path)).not.toContain("/users");
    }
  });

  it("finds the item a path belongs to on a segment boundary", () => {
    expect(navItemOf("/restrictions")?.path).toBe("/restrictions");
    expect(navItemOf("/restrictions/01K6P0A1B2C3D4E5F6G7H8J9KM")?.path).toBe("/restrictions");
    expect(navItemOf("/restrictions/new")?.path).toBe("/restrictions/new");
    expect(navItemOf("/occurrences/new")?.path).toBe("/occurrences/new");
    expect(navItemOf("/overview")?.path).toBe("/overview");
    expect(navItemOf("/restrictionsx")).toBeNull();
    expect(navItemOf("/login")).toBeNull();
  });
});
