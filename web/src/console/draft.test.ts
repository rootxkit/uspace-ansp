// The drawn area's shape: positions in, the API's geometry out.
import { describe, expect, it } from "vitest";
import { pointOf, polygonOf, verticesOf, type Position } from "./draft";

describe("the geometry", () => {
  const tri: Position[] = [
    [44.78, 41.7],
    [44.82, 41.7],
    [44.8, 41.73],
  ];

  it("closes the ring of three or more vertices", () => {
    expect(polygonOf(tri)).toEqual({ type: "Polygon", coordinates: [[...tri, [44.78, 41.7]]] });
  });

  it("does not repeat a closing position already there", () => {
    expect(polygonOf([...tri, [44.78, 41.7]])).toEqual(polygonOf(tri));
  });

  it("is null under three distinct vertices", () => {
    expect(polygonOf(tri.slice(0, 2))).toBeNull();
    expect(polygonOf([...tri.slice(0, 2), [44.78, 41.7]])).toBeNull();
    expect(polygonOf([])).toBeNull();
  });

  it("is a Point for a circle's centre", () => {
    expect(pointOf([44.8, 41.71])).toEqual({ type: "Point", coordinates: [44.8, 41.71] });
  });

  it("reads a restriction's vertices back without the closing position", () => {
    expect(verticesOf(polygonOf(tri) ?? { type: "Polygon", coordinates: [] })).toEqual(tri);
    expect(verticesOf(pointOf([44.8, 41.71]))).toEqual([[44.8, 41.71]]);
    expect(verticesOf({ type: "LineString", coordinates: [] })).toEqual([]);
  });
});
