// The drawn area's shape: text in, the API's geometry out.
import { describe, expect, it } from "vitest";
import { parseVertices, pointOf, polygonOf, roundClick, verticesOf, verticesText, type Position } from "./draft";

describe("the vertex list", () => {
  it("reads one lng, lat per line, with commas or spaces, blank lines skipped", () => {
    expect(parseVertices("44.78, 41.70\n\n44.82 41.70\r\n44.82;41.73")).toEqual({
      vertices: [
        [44.78, 41.7],
        [44.82, 41.7],
        [44.82, 41.73],
      ],
    });
  });

  it("names the line that is not a pair, and the one out of range", () => {
    expect(parseVertices("44.78, 41.70\n44.82")).toEqual({ line: 2, problem: "pair" });
    expect(parseVertices("44.78, 41.70, 3")).toEqual({ line: 1, problem: "pair" });
    expect(parseVertices("x, 41.70")).toEqual({ line: 1, problem: "pair" });
    expect(parseVertices("181, 41.70")).toEqual({ line: 1, problem: "range" });
    expect(parseVertices("44.78, -91")).toEqual({ line: 1, problem: "range" });
  });

  it("writes what it reads", () => {
    const vs: Position[] = [
      [44.78, 41.7],
      [44.82, 41.7],
    ];
    expect(parseVertices(verticesText(vs))).toEqual({ vertices: vs });
  });

  it("rounds a click to the list's decimals", () => {
    expect(roundClick([44.123456789, 41.987654321])).toEqual([44.123457, 41.987654]);
  });
});

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
