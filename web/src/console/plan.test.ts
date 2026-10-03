// The plan body: the form's values and the drawn area become the
// RestrictionCreate the API takes; a missing area is named on its field.
import { describe, expect, it } from "vitest";
import type { Position } from "./draft";
import { planBody, planSchema, type PlanValues } from "./plan";

const VALUES: PlanValues = {
  uspace_airspace_id: "GEOTU01",
  zone_type: "PROHIBITED",
  lower_m: 0,
  lower_ref: "AMSL",
  upper_m: 1200,
  upper_ref: "WGS84",
  starts_at: "2026-10-02T12:00:00Z",
  ends_at: "2026-10-02T16:00:00Z",
  reason_text: "Search and rescue (synthetic)",
  radius_m: null,
  confirm_chain: false,
};
const REASONS = { polygon: "p", centre: "c", radius: "r" };
const TRI: Position[] = [
  [44.78, 41.7],
  [44.82, 41.7],
  [44.8, 41.73],
];

describe("planBody", () => {
  it("sends a closed Polygon with radius_m null and no confirm_chain", () => {
    expect(planBody(VALUES, "polygon", TRI, null, REASONS)).toEqual({
      body: {
        uspace_airspace_id: "GEOTU01",
        zone_type: "PROHIBITED",
        lower_m: 0,
        lower_ref: "AMSL",
        upper_m: 1200,
        upper_ref: "WGS84",
        starts_at: "2026-10-02T12:00:00Z",
        ends_at: "2026-10-02T16:00:00Z",
        reason_text: "Search and rescue (synthetic)",
        geometry: { type: "Polygon", coordinates: [[...TRI, [44.78, 41.7]]] },
        radius_m: null,
      },
    });
  });

  it("sends confirm_chain only when ticked", () => {
    const b = planBody({ ...VALUES, confirm_chain: true }, "polygon", TRI, null, REASONS);
    expect("body" in b && b.body.confirm_chain).toBe(true);
  });

  it("names the geometry when the polygon has under three vertices", () => {
    expect(planBody(VALUES, "polygon", TRI.slice(0, 2), null, REASONS)).toEqual({ errors: [{ field: "geometry", reason: "p" }] });
  });

  it("sends a Point with its radius for a circle", () => {
    const b = planBody({ ...VALUES, radius_m: 500 }, "circle", [], [44.8, 41.71], REASONS);
    expect(b).toMatchObject({ body: { geometry: { type: "Point", coordinates: [44.8, 41.71] }, radius_m: 500 } });
  });

  it("names the centre and the radius a circle lacks", () => {
    expect(planBody(VALUES, "circle", [], null, REASONS)).toEqual({
      errors: [
        { field: "geometry", reason: "c" },
        { field: "radius_m", reason: "r" },
      ],
    });
  });
});

describe("planSchema", () => {
  it("passes the shape, and refuses AGL, an empty reason and a time that is not UTC", () => {
    expect(planSchema.safeParse(VALUES).success).toBe(true);
    expect(planSchema.safeParse({ ...VALUES, lower_ref: "AGL" }).success).toBe(false);
    expect(planSchema.safeParse({ ...VALUES, reason_text: "  " }).success).toBe(false);
    expect(planSchema.safeParse({ ...VALUES, starts_at: "2026-10-02T12:00:00+04:00" }).success).toBe(false);
  });
});
