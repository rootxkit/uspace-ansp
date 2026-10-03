"use client";

// The console's map: the kit's MapView on the self-hosted basemap of this
// origin (/basemap/, M38), the restrictions in the kit's symbology
// (RestrictionLayer), and, in the editor, the area being drawn. The map
// shows what the API says and what the supervisor clicks; it measures,
// contains and buffers nothing (no geometry library in web/, T12).
import { useEffect, useMemo, useSyncExternalStore, type ReactNode } from "react";
import type { GeoJSONSource, Map as MapLibreMap, MapMouseEvent } from "maplibre-gl";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { RestrictionLayer, resolveColour, useLayer, type RestrictionView } from "@rootxkit/uspace-ui/layers";
import { MapView, useMap } from "@rootxkit/uspace-ui/map";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { useRuntimeConfig } from "../components/Providers";
import type { Position } from "./draft";

function noSubscribe(): () => void {
  return () => undefined;
}

/** The map with the restrictions; `children` are further layers. */
export function ConsoleMap(props: {
  restrictions: readonly RestrictionView[];
  onSelect?(identifier: string): void;
  children?: ReactNode;
  className?: string;
}) {
  const t = useT();
  const { lang } = useLang();
  const { resolved } = useTheme();
  const cfg = useRuntimeConfig();
  // The basemap is read from this origin's /basemap/; null while rendering on the server.
  const origin = useSyncExternalStore(
    noSubscribe,
    () => window.location.origin,
    () => null,
  );
  if (cfg.mapView === null) {
    return (
      <p role="alert" data-testid="map-not-configured" className="m-0 p-4 text-[var(--us-danger)]">
        {t("ansp.map.not_configured", { problem: cfg.mapViewProblem ?? "" })}
      </p>
    );
  }
  return (
    <div className={`relative ${props.className ?? "h-[50vh]"}`} data-testid="console-map">
      {origin !== null && (
        <MapView
          className="absolute inset-0"
          basemap={{ baseUrl: origin }}
          initial={{ center: cfg.mapView.center, zoom: cfg.mapView.zoom, bearing: 0, pitch: 0 }}
          lang={lang}
          scheme={resolved}
        >
          <RestrictionLayer id="ansp-restrictions" restrictions={props.restrictions} {...(props.onSelect === undefined ? {} : { onSelect: props.onSelect })} />
          {props.children}
        </MapView>
      )}
    </div>
  );
}

/** The draft's GeoJSON: the clicked vertices as points and, from three on, the ring as drawn. */
export function draftCollection(vertices: readonly Position[], closed: boolean): GeoJSON.FeatureCollection {
  const features: GeoJSON.Feature[] = vertices.map((v, i) => ({
    type: "Feature",
    properties: { index: i },
    geometry: { type: "Point", coordinates: [v[0], v[1]] },
  }));
  if (vertices.length >= 2) {
    const line = vertices.map((v) => [v[0], v[1]]);
    const first = vertices[0];
    if (closed && first !== undefined && vertices.length >= 3) line.push([first[0], first[1]]);
    features.push({ type: "Feature", properties: {}, geometry: { type: "LineString", coordinates: line } });
  }
  return { type: "FeatureCollection", features };
}

const DRAFT_ID = "ansp-draft";

/**
 * The area being drawn, on the enclosing ConsoleMap: the vertices and
 * their outline in the accent colour, and every click on the map handed
 * to `onClick` as [lng, lat] in WGS84 degrees, as MapLibre reports it.
 */
export function DraftLayer(props: { vertices: readonly Position[]; closed: boolean; onClick(at: Position): void }) {
  const data = useMemo(() => draftCollection(props.vertices, props.closed), [props.vertices, props.closed]);
  useLayer<GeoJSON.FeatureCollection>({
    id: DRAFT_ID,
    data,
    build(map: MapLibreMap) {
      const colour = resolveColour(map, "--us-accent");
      map.addSource(DRAFT_ID, { type: "geojson", data: { type: "FeatureCollection", features: [] } });
      map.addLayer({
        id: `${DRAFT_ID}-line`,
        type: "line",
        source: DRAFT_ID,
        filter: ["==", ["geometry-type"], "LineString"],
        paint: { "line-color": colour, "line-width": 2, "line-dasharray": [2, 1] },
      });
      map.addLayer({
        id: `${DRAFT_ID}-points`,
        type: "circle",
        source: DRAFT_ID,
        filter: ["==", ["geometry-type"], "Point"],
        paint: { "circle-color": colour, "circle-radius": 5, "circle-stroke-width": 1, "circle-stroke-color": "#ffffff" },
      });
      return [`${DRAFT_ID}-line`, `${DRAFT_ID}-points`];
    },
    update(map: MapLibreMap, d: GeoJSON.FeatureCollection) {
      (map.getSource(DRAFT_ID) as GeoJSONSource | undefined)?.setData(d);
    },
  });
  const map = useMap();
  const { onClick } = props;
  useEffect(() => {
    if (map === null) return;
    const handler = (e: MapMouseEvent) => onClick([e.lngLat.lng, e.lngLat.lat]);
    map.on("click", handler);
    return () => {
      map.off("click", handler);
    };
  }, [map, onClick]);
  return null;
}
