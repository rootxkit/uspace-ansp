// What the manned picture says about one aircraft, in words: its
// identity, its two altitudes each with its datum (fmtAltitude: pressure
// altitude is never called AMSL, R-09; nothing is summed or converted),
// speed and track as sent, and its state with its age and, for a
// disabled source, who switched it off (B-11). The age of a stale
// aircraft is always shown; nothing is called lost (C-12).
import { fmtAge, fmtAltitude, fmtHeading, fmtSpeed, type Lang, type Translate } from "@rootxkit/uspace-ui/i18n";
import type { StatusSource } from "@rootxkit/uspace-ui/live";
import { disabledBy, type Aircraft, type ApiAdapterState, type Drawn } from "./manned";
import type { StreamStatus } from "./stream";

/** The aircraft's name: callsign and ICAO address, or the address alone. */
export function identText(a: Pick<Aircraft, "callsign" | "icao24">): string {
  return a.callsign === null ? a.icao24 : `${a.callsign} · ${a.icao24}`;
}

/** Both altitudes, each with its datum; the WGS84 height only when sent. */
export function altitudeText(a: Pick<Aircraft, "altPressureM" | "altWgs84M">, t: Translate, lang: Lang): string {
  if (a.altPressureM === null && a.altWgs84M === null) return t("ansp.picture.alt_none");
  const parts: string[] = [];
  parts.push(a.altPressureM === null ? t("ansp.picture.alt_pressure_none") : fmtAltitude(a.altPressureM, "pressure", lang));
  if (a.altWgs84M !== null) parts.push(fmtAltitude(a.altWgs84M, "WGS84", lang));
  return parts.join(" · ");
}

/** Ground speed and track as sent. */
export function motionText(a: Pick<Aircraft, "gsMs" | "trackDeg">, lang: Lang): string {
  return `${fmtSpeed(a.gsMs, lang)} · ${fmtHeading(a.trackDeg)}`;
}

/** The state line: live, backlog, stale (age), source disabled by whom. */
export function stateText(a: Aircraft, d: Drawn, sources: readonly StatusSource[], staleAfterS: number | null, t: Translate, lang: Lang): string {
  const age = d.ageS === null ? t("ansp.picture.age_unknown") : fmtAge(d.ageS, lang);
  switch (d.state) {
    case "live":
      return t("ansp.picture.state.live", { age });
    case "backlog":
      return t("ansp.picture.state.backlog", { age });
    case "stale":
      return d.agedHere && staleAfterS !== null
        ? t("ansp.picture.state.stale_here", { age, threshold: staleAfterS })
        : t("ansp.picture.state.stale", { age });
    case "source_disabled": {
      const by = disabledBy(a.sourceInstance, sources);
      if (by === null || by.who === null) return t("ansp.picture.state.source_disabled_unknown", { age, adapter: a.sourceInstance });
      if (by.by === "type") return t("ansp.picture.state.source_disabled_type", { who: by.who, age });
      return t("ansp.picture.state.source_disabled", { who: by.who, age, adapter: a.sourceInstance });
    }
  }
}

/** The map label: identity, altitudes, motion, state; one per line. */
export function labelText(a: Aircraft, d: Drawn, sources: readonly StatusSource[], staleAfterS: number | null, t: Translate, lang: Lang): string {
  return [identText(a), altitudeText(a, t, lang), motionText(a, lang), stateText(a, d, sources, staleAfterS, t, lang)].join("\n");
}

/** The symbol's name for tests and the legend: state and relevance. */
export function symbolOf(a: Pick<Aircraft, "relevant">, d: Pick<Drawn, "state">): string {
  const r = a.relevant === true ? "relevant" : a.relevant === false ? "other" : "unstated";
  return `${d.state}-${r}`;
}

/** One adapter in words: its state, age, and who disabled it (B-11). */
export function adapterText(a: ApiAdapterState, sources: readonly StatusSource[], t: Translate, lang: Lang): string {
  const age = a.age_s === null || a.age_s === undefined ? t("ansp.picture.age_unknown") : fmtAge(a.age_s, lang);
  if (a.state === "disabled") {
    const by = disabledBy(a.id, sources);
    return by === null || by.who === null
      ? t("ansp.picture.adapter.disabled_unknown", { id: a.id })
      : t("ansp.picture.adapter.disabled", { id: a.id, who: by.who });
  }
  return t(`ansp.picture.adapter.${a.state}`, { id: a.id, age });
}

/** The adapters as one line, for the empty picture (SC-22). */
export function adaptersLine(s: Pick<StreamStatus, "adapters" | "sources">, t: Translate, lang: Lang): string {
  if (s.adapters === null || s.adapters.length === 0) return t("ansp.picture.adapters_none");
  return s.adapters.map((a) => adapterText(a, s.sources, t, lang)).join("; ");
}

