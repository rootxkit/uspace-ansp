// The plan body: the form's values and the drawn area become the
// RestrictionCreate the API takes; a missing area is named on its field.
import { describe, expect, it } from "vitest";
import type { DrawOutline } from "@rootxkit/uspace-ui/model";
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
  confirm_chain: false,
};
const REASONS = { polygon: "p", centre: "c", radius: "r" };
const TRI: DrawOutline = {
  kind: "polygon",
  vertices: [
    { lng: 44.78, lat: 41.7 },
    { lng: 44.82, lat: 41.7 },
    { lng: 44.8, lat: 41.73 },
  ],
};

describe("planBody", () => {
  it("sends a closed Polygon with radius_m null and no confirm_chain", () => {
    expect(planBody(VALUES, TRI, REASONS)).toEqual({
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
        geometry: { type: "Polygon", coordinates: [[[44.78, 41.7], [44.82, 41.7], [44.8, 41.73], [44.78, 41.7]]] },
        radius_m: null,
      },
    });
  });

  it("sends confirm_chain only when ticked", () => {
    const b = planBody({ ...VALUES, confirm_chain: true }, TRI, REASONS);
    expect("body" in b && b.body.confirm_chain).toBe(true);
  });

  it("names the geometry when the polygon has under three vertices", () => {
    expect(planBody(VALUES, { kind: "polygon", vertices: TRI.vertices.slice(0, 2) }, REASONS)).toEqual({ errors: [{ field: "geometry", reason: "p" }] });
  });

  it("sends a circle as its Point and radius, never as an outline", () => {
    const b = planBody(VALUES, { kind: "circle", center: { lng: 44.8, lat: 41.71 }, radiusM: 500 }, REASONS);
    expect(b).toMatchObject({ body: { geometry: { type: "Point", coordinates: [44.8, 41.71] }, radius_m: 500 } });
  });

  it("names the centre and the radius a circle lacks", () => {
    expect(planBody(VALUES, { kind: "circle", center: null, radiusM: null }, REASONS)).toEqual({
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
