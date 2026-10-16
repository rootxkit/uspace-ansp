// The editor's outline: the vertex bound pinned to the contract, the
// circle's query, and the API's outline read as it was sent (row 53).
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConsoleClient } from "../api/client";
import { MAX_VERTICES, OUTLINE_CACHE_MAX, circleAreaOf, circleKey, circleOutline, circleQuery, clearOutlineCache, outlineOfAnswer, undrawnCircles, verticesOfOutline } from "./outline";

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

describe("circleAreaOf", () => {
  it("is the centre and radius of a circle restriction, null for a polygon or an incomplete circle", () => {
    expect(circleAreaOf({ geometry: { type: "Point", coordinates: [44.8, 41.715] }, radius_m: 1500 })).toEqual({ lat: 41.715, lng: 44.8, radiusM: 1500 });
    expect(circleAreaOf({ geometry: { type: "Polygon", coordinates: [] }, radius_m: null })).toBeNull();
    expect(circleAreaOf({ geometry: { type: "Point", coordinates: [44.8, 41.715] }, radius_m: null })).toBeNull();
    expect(circleAreaOf({ geometry: { type: "Point", coordinates: [44.8] }, radius_m: 10 })).toBeNull();
  });
});

describe("circleOutline", () => {
  const ring = [
    [44.8, 41.73],
    [44.79, 41.71],
    [44.81, 41.71],
    [44.8, 41.73],
  ];
  const a = { lat: 41.715, lng: 44.8, radiusM: 1500 };

  function fake(answer: () => Promise<{ data?: unknown }>) {
    const GET = vi.fn(answer);
    return { client: { GET } as unknown as ConsoleClient, GET };
  }

  beforeEach(() => clearOutlineCache());

  it("asks once per circle however often it is listed, and draws the API's ring", async () => {
    const { client, GET } = fake(async () => ({ data: { outline: { type: "Polygon", coordinates: [ring] } } }));
    const first = await circleOutline(client, a);
    const again = await Promise.all([circleOutline(client, a), circleOutline(client, { ...a })]);
    expect(first).toEqual({ type: "Polygon", coordinates: [ring] });
    expect(again).toEqual([first, first]);
    expect(GET).toHaveBeenCalledTimes(1);
    expect(GET).toHaveBeenCalledWith("/v1/outlines/circle", { params: { query: { lat: 41.715, lng: 44.8, radius_m: 1500 } } });
    // The pair: a different circle is a different question.
    await circleOutline(client, { ...a, radiusM: 2000 });
    expect(GET).toHaveBeenCalledTimes(2);
  });

  it("caches a refusal as no outline, and asks again after a failed call", async () => {
    const refused = fake(async () => ({ data: undefined }));
    expect(await circleOutline(refused.client, a)).toBeNull();
    expect(await circleOutline(refused.client, a)).toBeNull();
    expect(refused.GET).toHaveBeenCalledTimes(1);

    clearOutlineCache();
    let fail = true;
    const flaky = fake(async () => {
      if (fail) throw new Error("network");
      return { data: { outline: { type: "Polygon", coordinates: [ring] } } };
    });
    await expect(circleOutline(flaky.client, a)).rejects.toThrow("network");
    fail = false;
    expect(await circleOutline(flaky.client, a)).not.toBeNull();
    expect(flaky.GET).toHaveBeenCalledTimes(2);
  });

  it("keeps at most OUTLINE_CACHE_MAX circles", async () => {
    const { client, GET } = fake(async () => ({ data: undefined }));
    for (let i = 0; i <= OUTLINE_CACHE_MAX; i++) await circleOutline(client, { ...a, radiusM: i + 1 });
    await circleOutline(client, { ...a, radiusM: 1 });
    expect(GET).toHaveBeenCalledTimes(OUTLINE_CACHE_MAX + 2);
  });
});

describe("undrawnCircles", () => {
  it("counts only the circles the API gave no outline for, not those still loading", () => {
    const a = { lat: 1, lng: 2, radiusM: 3 };
    const b = { lat: 4, lng: 5, radiusM: 6 };
    const c = { lat: 7, lng: 8, radiusM: 9 };
    const poly: GeoJSON.Polygon = { type: "Polygon", coordinates: [] };
    const known = new Map<string, GeoJSON.Polygon | null>([
      [circleKey(a), poly],
      [circleKey(b), null],
    ]);
    expect(undrawnCircles([a, b, c], known)).toBe(1);
  });
});
