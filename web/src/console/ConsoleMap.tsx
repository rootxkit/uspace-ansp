"use client";

// The console's map: the kit's MapView on the self-hosted basemap of this
// origin (/basemap/, M38), the restrictions in the kit's symbology
// (RestrictionLayer), and, in the editor, the kit's DrawLayer as a child.
// The map shows what the API says and what the supervisor clicks; it
// measures, contains and buffers nothing (no geometry library in web/,
// T12).
import { useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import type { Map as MapLibreMap } from "maplibre-gl";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { RestrictionLayer, type RestrictionView } from "@rootxkit/uspace-ui/layers";
import { MapView } from "@rootxkit/uspace-ui/map";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { useRuntimeConfig } from "../components/Providers";

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

/**
 * A hidden marker of a layer on the enclosing map: `data-idle` is true
 * once the map has drawn the layer's current data (MapLibre's idle event
 * after it was handed over). For the screenshots and smoke runs to wait
 * on a condition, never on time; it shows nothing.
 */
export function LayerReady({ map, data, name }: { map: MapLibreMap | null; data: unknown; name: string }) {
  const [drawn, setDrawn] = useState<unknown>(null);
  useEffect(() => {
    if (map === null) return;
    const done = () => setDrawn(data);
    map.once("idle", done);
    map.triggerRepaint();
    return () => {
      map.off("idle", done);
    };
  }, [map, data]);
  return <span hidden data-testid={`layer-${name}`} data-idle={map !== null && drawn === data} />;
}
