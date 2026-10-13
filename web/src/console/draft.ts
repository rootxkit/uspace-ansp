// The area a supervisor draws as the API's geometry (api/openapi.yaml
// RestrictionGeometry: a GeoJSON Polygon in WGS84 [lng, lat], exterior
// ring closed, or a Point with radius_m). This is shape only, like a form
// schema: the numbers are passed on as typed and clicked (the kit's
// DrawLayer and OutlineFields, src/console/outline.ts), the ring is
// closed by repeating its first position, and every judgement
// (self-intersection, area, vertices, containment in the U-space
// airspace) is the API's, through uspace-core (T12).

/** [lng, lat] in WGS84 degrees. */
export type Position = [number, number];

/** The fewest distinct vertices a ring has (a triangle); a shape rule, not a judgement. */
export const MIN_VERTICES = 3;

export interface PolygonGeometry {
  type: "Polygon";
  coordinates: Position[][];
}

export interface PointGeometry {
  type: "Point";
  coordinates: Position;
}

/**
 * The Polygon of the vertices, its ring closed (the first position
 * repeated at the end unless it is there already); null under
 * MIN_VERTICES.
 */
export function polygonOf(vertices: readonly Position[]): PolygonGeometry | null {
  const ring = vertices.map((v): Position => [v[0], v[1]]);
  const first = ring[0];
  const last = ring[ring.length - 1];
  if (first !== undefined && last !== undefined && ring.length > 1 && first[0] === last[0] && first[1] === last[1]) ring.pop();
  if (ring.length < MIN_VERTICES || first === undefined) return null;
  return { type: "Polygon", coordinates: [[...ring, [first[0], first[1]]]] };
}

/** The Point of a circle's centre. */
export function pointOf(centre: Position): PointGeometry {
  return { type: "Point", coordinates: [centre[0], centre[1]] };
}

/** The vertices of a restriction's Polygon, without the closing position. */
export function verticesOf(geometry: { type: string; coordinates: unknown }): Position[] {
  if (geometry.type === "Point") {
    const c = geometry.coordinates;
    return Array.isArray(c) && typeof c[0] === "number" && typeof c[1] === "number" ? [[c[0], c[1]]] : [];
  }
  if (geometry.type !== "Polygon" || !Array.isArray(geometry.coordinates)) return [];
  const ring = geometry.coordinates[0];
  if (!Array.isArray(ring)) return [];
  const vs = ring.filter((p): p is Position => Array.isArray(p) && typeof p[0] === "number" && typeof p[1] === "number").map((p): Position => [p[0], p[1]]);
  const first = vs[0];
  const last = vs[vs.length - 1];
  if (vs.length > 1 && first !== undefined && last !== undefined && first[0] === last[0] && first[1] === last[1]) vs.pop();
  return vs;
}
