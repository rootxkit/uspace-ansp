"use client";

// The manned aircraft on the enclosing ConsoleMap, in the kit's track
// symbology for trust class surveillance (a square; with the arrow when
// the feed sent a track, rotated by it as sent): live in the
// surveillance colour, stale in the stale-age colour and faded, a
// disabled source in the muted colour and faded further, a backlog
// sample in the ageing colour; a relevant aircraft (inside a U-space
// volume plus the margin, as the feed flagged it) larger and ringed, the
// rest smaller. Each is drawn at its last position with its label,
// never moved by the browser (B-13). The kit 0.1.0-rc.1 has no
// MannedLayer (docs/PLAN.md section 15 row 51); this is built on its
// useLayer, icons and tokens.
import { useMemo } from "react";
import type { ExpressionSpecification, GeoJSONSource, Map as MapLibreMap } from "maplibre-gl";
import { mapFontstack } from "@rootxkit/uspace-ui/fonts";
import { putTrackIcons, resolveColour, useLayer } from "@rootxkit/uspace-ui/layers";
import { trackIconId } from "@rootxkit/uspace-ui/symbology";
import type { DrawnState } from "./manned";

/** One aircraft as the layer draws it. */
export interface MannedFeature {
  icao24: string;
  lng: number;
  lat: number;
  state: DrawnState;
  relevant: boolean | null;
  trackDeg: number | null;
  label: string;
}

const ID = "ansp-manned";

/** The token each drawn state is painted with (the kit's tokens). */
export const STATE_TOKEN: Record<DrawnState, string> = {
  live: "--us-trust-surveillance",
  backlog: "--us-age-aging",
  stale: "--us-age-stale",
  source_disabled: "--us-text-muted",
};

/** Opacity per drawn state, and the factor for an aircraft outside the relevant airspace. Display-only. */
export const STATE_OPACITY: Record<DrawnState, number> = { live: 1, backlog: 0.9, stale: 0.6, source_disabled: 0.45 };
export const OTHER_OPACITY = 0.65;
/** Icon sizes: relevant, and the rest. Display-only. */
export const RELEVANT_SIZE = 1;
export const OTHER_SIZE = 0.7;
const RING_RADIUS_PX = 17;
const LABEL_OFFSET_EM: [number, number] = [0, 1.4];
const LABEL_SIZE_PX = 11;

/** The features of the aircraft (properties the paint reads). */
export function mannedCollection(items: readonly MannedFeature[]): GeoJSON.FeatureCollection {
  return {
    type: "FeatureCollection",
    features: items.map((m) => ({
      type: "Feature",
      id: m.icao24,
      properties: {
        icao24: m.icao24,
        state: m.state,
        relevant: m.relevant === true,
        icon: trackIconId("surveillance", m.trackDeg !== null),
        rotate: m.trackDeg ?? 0,
        opacity: STATE_OPACITY[m.state] * (m.relevant === true ? 1 : OTHER_OPACITY),
        size: m.relevant === true ? RELEVANT_SIZE : OTHER_SIZE,
        label: m.label,
      },
      geometry: { type: "Point", coordinates: [m.lng, m.lat] },
    })),
  };
}

export function MannedLayer({ aircraft }: { aircraft: readonly MannedFeature[] }) {
  const data = useMemo(() => mannedCollection(aircraft), [aircraft]);
  useLayer<GeoJSON.FeatureCollection>({
    id: ID,
    data,
    build(map: MapLibreMap) {
      putTrackIcons(map);
      const colour = (["live", "backlog", "stale", "source_disabled"] as const).flatMap((s) => [s, resolveColour(map, STATE_TOKEN[s])]);
      const stateColour = ["match", ["get", "state"], ...colour, resolveColour(map, "--us-age-unknown")] as unknown as ExpressionSpecification;
      const halo = resolveColour(map, "--us-surface");
      map.addSource(ID, { type: "geojson", data: { type: "FeatureCollection", features: [] } });
      map.addLayer({
        id: `${ID}-ring`,
        type: "circle",
        source: ID,
        filter: ["==", ["get", "relevant"], true],
        paint: {
          "circle-radius": RING_RADIUS_PX,
          "circle-color": "rgba(0,0,0,0)",
          "circle-stroke-color": stateColour,
          "circle-stroke-width": 2,
          "circle-stroke-opacity": ["get", "opacity"],
        },
      });
      map.addLayer({
        id: `${ID}-icon`,
        type: "symbol",
        source: ID,
        layout: {
          "icon-image": ["get", "icon"],
          "icon-rotate": ["get", "rotate"],
          "icon-rotation-alignment": "map",
          "icon-size": ["get", "size"],
          "icon-allow-overlap": true,
          "icon-ignore-placement": true,
        },
        paint: { "icon-color": stateColour, "icon-opacity": ["get", "opacity"], "icon-halo-color": halo, "icon-halo-width": 1 },
      });
      map.addLayer({
        id: `${ID}-label`,
        type: "symbol",
        source: ID,
        layout: {
          "text-field": ["get", "label"],
          "text-font": [mapFontstack],
          "text-size": LABEL_SIZE_PX,
          "text-offset": LABEL_OFFSET_EM,
          "text-anchor": "top",
          "text-justify": "left",
          "text-optional": true,
        },
        paint: { "text-color": resolveColour(map, "--us-text"), "text-halo-color": halo, "text-halo-width": 1.5, "text-opacity": ["get", "opacity"] },
      });
      return [`${ID}-ring`, `${ID}-icon`, `${ID}-label`];
    },
    update(map: MapLibreMap, d: GeoJSON.FeatureCollection) {
      (map.getSource(ID) as GeoJSONSource | undefined)?.setData(d);
    },
  });
  return null;
}
