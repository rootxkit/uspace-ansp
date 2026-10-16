"use client";

// The restriction editor's outline (docs/PLAN.md section 15 row 53): the
// kit's DrawOutline as the supervisor draws it (layers/DrawLayer) or
// types it (form/OutlineFields), the API's geometry it becomes, and a
// circle's outline as the API drew it (GET /v1/outlines/circle). Shape
// only: a position is passed on as clicked or typed, a ring is closed by
// repeating its first position, and every judgement (self-intersection,
// area, containment in the U-space airspace) is the API's. A circle's
// outline is never drawn here: web/ does no geodesy (T12).
import { useEffect, useState } from "react";
import type { DrawOutline, DrawPoint } from "@rootxkit/uspace-ui/model";
import type { ConsoleClient } from "../api/client";
import type { Position } from "./draft";

/**
 * The most vertices the editor takes: api/openapi.yaml GeoJSONPolygon's
 * ring holds at most 1000 positions, the last repeating the first.
 * Pinned against the contract by outline.test.ts.
 */
export const MAX_VERTICES = 999;

/** A drawn point as a GeoJSON position [lng, lat]. */
export function positionOf(p: DrawPoint): Position {
  return [p.lng, p.lat];
}

/** The polygon's vertices as positions, in the order drawn or typed. */
export function verticesOfOutline(outline: DrawOutline): Position[] {
  return outline.kind === "polygon" ? outline.vertices.map(positionOf) : [];
}

/** What the map shows of a circle: the API's outline, or the reason it has none. */
export type CircleOutlineState =
  | { kind: "none" }
  | { kind: "loading" }
  | { kind: "drawn"; outline: GeoJSON.Polygon }
  | { kind: "refused" };

/** The query of the circle's outline, or null while the circle lacks its centre or radius. */
export function circleQuery(outline: DrawOutline): { lat: number; lng: number; radius_m: number } | null {
  if (outline.kind !== "circle" || outline.center === null || outline.radiusM === null) return null;
  return { lat: outline.center.lat, lng: outline.center.lng, radius_m: outline.radiusM };
}

/** The outline in an answer of GET /v1/outlines/circle, or null when it is not a ring. */
export function outlineOfAnswer(data: unknown): GeoJSON.Polygon | null {
  if (typeof data !== "object" || data === null) return null;
  const o = (data as { outline?: unknown }).outline;
  if (typeof o !== "object" || o === null) return null;
  const { type, coordinates } = o as { type?: unknown; coordinates?: unknown };
  if (type !== "Polygon" || !Array.isArray(coordinates) || coordinates.length < 1) return null;
  const ok = coordinates.every(
    (ring) => Array.isArray(ring) && ring.length >= 4 && ring.every((p) => Array.isArray(p) && p.length === 2 && p.every((n) => typeof n === "number" && Number.isFinite(n))),
  );
  return ok ? { type: "Polygon", coordinates: coordinates as GeoJSON.Position[][] } : null;
}

/**
 * The circle's outline as the API drew it for the outline being edited:
 * asked again whenever the centre or the radius changes, the previous
 * request aborted, and an answer for an outline no longer shown dropped.
 * A polygon, or a circle without its centre or radius, has none.
 */
export function useCircleOutline(client: ConsoleClient, outline: DrawOutline): CircleOutlineState {
  const query = circleQuery(outline);
  const lat = query?.lat ?? null;
  const lng = query?.lng ?? null;
  const radiusM = query?.radius_m ?? null;
  const key = lat === null || lng === null || radiusM === null ? null : `${lat},${lng},${radiusM}`;
  const [state, setState] = useState<{ key: string | null; value: CircleOutlineState }>({ key: null, value: { kind: "none" } });
  useEffect(() => {
    if (key === null || lat === null || lng === null || radiusM === null) return;
    const ctrl = new AbortController();
    client
      .GET("/v1/outlines/circle", { params: { query: { lat, lng, radius_m: radiusM } }, signal: ctrl.signal })
      .then(({ data }) => {
        const drawn = outlineOfAnswer(data);
        setState({ key, value: drawn === null ? { kind: "refused" } : { kind: "drawn", outline: drawn } });
      })
      .catch(() => {
        if (!ctrl.signal.aborted) setState({ key, value: { kind: "refused" } });
      });
    return () => ctrl.abort();
  }, [client, key, lat, lng, radiusM]);
  if (key === null) return { kind: "none" };
  return state.key === key ? state.value : { kind: "loading" };
}

/** One circle restriction's area, as the outline request needs it. */
export interface CircleArea {
  lat: number;
  lng: number;
  radiusM: number;
}

/** The circle of a restriction's area (a Point with radius_m), or null when it is not a circle. */
export function circleAreaOf(area: { geometry: { type: string; coordinates?: unknown }; radius_m?: number | null }): CircleArea | null {
  if (area.geometry.type !== "Point") return null;
  const c = area.geometry.coordinates;
  const r = area.radius_m;
  if (!Array.isArray(c) || c.length < 2 || typeof c[0] !== "number" || typeof c[1] !== "number") return null;
  if (typeof r !== "number" || !Number.isFinite(r) || r <= 0) return null;
  return { lat: c[1], lng: c[0], radiusM: r };
}

/** The cache key of a circle: the values the API is asked about. */
export function circleKey(c: CircleArea): string {
  return `${c.lat},${c.lng},${c.radiusM}`;
}

/** The most circles whose outline is kept; the oldest goes first. */
export const OUTLINE_CACHE_MAX = 200;

const outlineCache = new Map<string, Promise<GeoJSON.Polygon | null>>();

/** Forgets every cached outline (tests). */
export function clearOutlineCache(): void {
  outlineCache.clear();
}

/**
 * The API's outline of one circle, asked once per circle: the request is
 * cached by its centre and radius, so a restriction listed again (a
 * reload, a pushed frame, another page) costs no request. A refusal is
 * cached as null; a failed call is not, so a later visit asks again.
 */
export function circleOutline(client: ConsoleClient, c: CircleArea): Promise<GeoJSON.Polygon | null> {
  const key = circleKey(c);
  const hit = outlineCache.get(key);
  if (hit !== undefined) return hit;
  const pending = client.GET("/v1/outlines/circle", { params: { query: { lat: c.lat, lng: c.lng, radius_m: c.radiusM } } }).then(
    ({ data }) => outlineOfAnswer(data),
    (e: unknown) => {
      outlineCache.delete(key);
      throw e;
    },
  );
  outlineCache.set(key, pending);
  while (outlineCache.size > OUTLINE_CACHE_MAX) {
    const oldest = outlineCache.keys().next();
    if (oldest.done === true) break;
    outlineCache.delete(oldest.value);
  }
  return pending;
}

/** What the maps know of the circles listed: the outline per key, null for a refused or unreachable one. */
export type CircleOutlines = ReadonlyMap<string, GeoJSON.Polygon | null>;

/**
 * The API's outlines of the circles listed, for the list and detail
 * maps. Each distinct circle is asked once (see circleOutline); a circle
 * not answered yet is absent from the result, one the API refused or
 * could not be reached for is null.
 */
export function useCircleOutlines(client: ConsoleClient, circles: readonly CircleArea[]): CircleOutlines {
  const wantedKey = [...new Set(circles.map(circleKey))].sort().join("|");
  const [answers, setAnswers] = useState<CircleOutlines>(new Map());
  useEffect(() => {
    let live = true;
    const byKey = new Map(circles.map((c) => [circleKey(c), c] as const));
    for (const [key, c] of byKey) {
      circleOutline(client, c).then(
        (outline) => {
          if (live) setAnswers((prev) => new Map(prev).set(key, outline));
        },
        () => {
          if (live) setAnswers((prev) => new Map(prev).set(key, null));
        },
      );
    }
    return () => {
      live = false;
    };
    // The circles' values are the dependency, not the array identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, wantedKey]);
  return answers;
}

/** The count of circles listed that the API gave no outline for (refused or unreachable). */
export function undrawnCircles(circles: readonly CircleArea[], outlines: CircleOutlines): number {
  return circles.filter((c) => outlines.get(circleKey(c)) === null).length;
}
