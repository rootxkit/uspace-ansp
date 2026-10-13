// The editor's outline: the vertex bound pinned to the contract, the
// circle's query, and the API's outline read as it was sent (row 53).
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { MAX_VERTICES, circleQuery, outlineOfAnswer, verticesOfOutline } from "./outline";

const spec = readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../api/openapi.yaml"), "utf8");

describe("MAX_VERTICES", () => {
  it("is the contract's GeoJSONPolygon ring bound less its closing position", () => {
    const block = spec.slice(spec.indexOf("    GeoJSONPolygon:"), spec.indexOf("    GeoJSONPoint:"));
    const ring = /items:\s+type: array\s+minItems: 4\s+maxItems: (\d+)/.exec(block);
    expect(ring?.[1]).toBeDefined();
    expect(MAX_VERTICES).toBe(Number(ring?.[1]) - 1);
  });
});

describe("circleQuery", () => {
  it("is the centre and radius of a complete circle", () => {
    expect(circleQuery({ kind: "circle", center: { lat: 41.715, lng: 44.8 }, radiusM: 1500 })).toEqual({ lat: 41.715, lng: 44.8, radius_m: 1500 });
  });

  it("is null for a circle without its centre or radius, and for a polygon", () => {
    expect(circleQuery({ kind: "circle", center: null, radiusM: 1500 })).toBeNull();
    expect(circleQuery({ kind: "circle", center: { lat: 41.7, lng: 44.8 }, radiusM: null })).toBeNull();
    expect(circleQuery({ kind: "polygon", vertices: [] })).toBeNull();
  });
});

describe("outlineOfAnswer", () => {
  const ring = [
    [44.8, 41.73],
    [44.79, 41.71],
    [44.81, 41.71],
    [44.8, 41.73],
  ];

  it("reads the API's outline as sent", () => {
    expect(outlineOfAnswer({ outline: { type: "Polygon", coordinates: [ring] }, vertices: 3 })).toEqual({ type: "Polygon", coordinates: [ring] });
  });

  it("refuses an answer that is not a ring, rather than drawing it", () => {
    expect(outlineOfAnswer(null)).toBeNull();
    expect(outlineOfAnswer({ outline: { type: "Point", coordinates: [44.8, 41.7] } })).toBeNull();
    expect(outlineOfAnswer({ outline: { type: "Polygon", coordinates: [ring.slice(0, 3)] } })).toBeNull();
    expect(outlineOfAnswer({ outline: { type: "Polygon", coordinates: [[...ring.slice(0, 3), ["x", 41.7]]] } })).toBeNull();
  });
});

describe("verticesOfOutline", () => {
  it("is [lng, lat] in the order drawn, and nothing for a circle", () => {
    expect(
      verticesOfOutline({
        kind: "polygon",
        vertices: [
          { lat: 41.7, lng: 44.78 },
          { lat: 41.71, lng: 44.82 },
        ],
      }),
    ).toEqual([
      [44.78, 41.7],
      [44.82, 41.71],
    ]);
    expect(verticesOfOutline({ kind: "circle", center: { lat: 41.7, lng: 44.8 }, radiusM: 10 })).toEqual([]);
  });
});
