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
