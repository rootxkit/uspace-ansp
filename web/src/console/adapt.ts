// The one hand-written mapping from the API's restrictions to the kit's
// view model (uspace-ui PLAN §3.14). It copies what the API said and
// decides nothing: the area is the restriction's own geometry as the API
// sent it (a circle is its centre Point: the API sends no outline of it,
// and drawing one would be geodesy, which web/ never does; the page says
// so beside the map), the limits and their references are the API's, and
// the name and message are the ED-318 feature's text in the viewer's
// language when the feature has it.
import type { RestrictionView } from "@rootxkit/uspace-ui/layers";
import type { Lang } from "@rootxkit/uspace-ui/i18n";
import type { ZoneView } from "@rootxkit/uspace-ui/model";
import type { components } from "../api/types";
import type { ApiRestriction } from "./delivery";

const ED318_LANG: Record<Lang, string> = { ka: "ka", en: "en" };

function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** The text of an ED-318 text list in `lang` (`ka-GE`, `en-GB`), else the first, else null. */
export function localText(v: unknown, lang: Lang): string | null {
  if (!Array.isArray(v)) return null;
  const items = v.map(obj).filter((x): x is Record<string, unknown> => x !== null && typeof x["text"] === "string");
  const want = ED318_LANG[lang];
  const hit = items.find((x) => typeof x["lang"] === "string" && x["lang"].toLowerCase().startsWith(want)) ?? items[0];
  return hit === undefined ? null : (hit["text"] as string);
}

/** True when the restriction's area is a circle (a Point with radius_m). */
export function isCircle(r: Pick<ApiRestriction, "geometry">): boolean {
  return r.geometry.type === "Point";
}

/** The kit's view of one restriction. */
export function toView(r: ApiRestriction, lang: Lang): RestrictionView {
  const p = obj(r.feature.properties);
  return {
    identifier: r.identifier,
    name: localText(p?.["name"], lang) ?? r.identifier,
    type: r.zone_type,
    variant: typeof p?.["variant"] === "string" ? p["variant"] : null,
    reason: Array.isArray(p?.["reason"]) ? p["reason"].filter((x): x is string => typeof x === "string") : [],
    message: localText(p?.["message"], lang),
    lowerLimitM: r.lower_m,
    lowerRef: r.lower_ref,
    upperLimitM: r.upper_m,
    upperRef: r.upper_ref,
    geometry: r.geometry as unknown as ZoneView["geometry"],
    applies: null,
    restrictionState: r.state,
    version: String(r.ansp_version),
    updatedAt: null,
    startsAt: r.starts_at,
    endsAt: r.ends_at,
  };
}

/** The kit's view of the area a restriction request asks for (02 F11), drawn before it is accepted. */
export function requestView(id: string, area: components["schemas"]["RestrictionArea"]): RestrictionView {
  return {
    identifier: id,
    name: null,
    type: "PROHIBITED",
    variant: null,
    reason: [],
    message: area.reason_text,
    lowerLimitM: area.lower_m,
    lowerRef: area.lower_ref,
    upperLimitM: area.upper_m,
    upperRef: area.upper_ref,
    geometry: area.geometry as unknown as ZoneView["geometry"],
    applies: null,
    restrictionState: "planned",
    version: null,
    updatedAt: null,
    startsAt: area.starts_at,
    endsAt: area.ends_at,
  };
}
