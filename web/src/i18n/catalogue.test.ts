// The ka and en catalogues: the same keys, no empty value, Georgian in
// ka, and every key the code names present (a literal key in app/ or
// src/, and every value of each enumeration a key is built from).
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import en from "./en.json";
import ka from "./ka.json";
import { LOGIN_SLUGS } from "../console/login";
import { CATEGORIES, CHANNELS } from "../console/occurrence";
import { THRESHOLDS } from "../console/policy";

const GEORGIAN = /[Ⴀ-ჿᲐ-Ჿⴀ-⴯]/u;
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) return sources(p);
    return /\.tsx?$/.test(name) && !name.endsWith(".test.ts") ? [p] : [];
  });
}

/** A key the translator finds: as is, or with a plural suffix. */
function present(cat: Record<string, string>, key: string): boolean {
  return Object.hasOwn(cat, key) || Object.hasOwn(cat, `${key}_other`);
}

/** The keys each dynamic prefix is completed with (the API's enumerations). */
const DYNAMIC: Record<string, readonly string[]> = {
  "ansp.restriction.state": ["planned", "active", "ended", "cancelled"],
  "ansp.restrictions.filter": ["all", "planned", "active", "ended", "cancelled"],
  "ansp.zone_type": ["PROHIBITED", "REQ_AUTHORIZATION"],
  "ansp.vertical_ref": ["AMSL", "WGS84"],
  "ansp.role": ["watch_supervisor", "viewer", "admin"],
  "ansp.changed_by": ["watch_supervisor", "viewer", "admin", "system"],
  "ansp.alarm.kind": ["cisp_not_published", "delivery_failed", "delivery_abandoned", "uss_notify_late", "occurrence_undelivered"],
  "ansp.alarm.state": ["open", "acknowledged", "cleared"],
  "ansp.delivery.uss_notify": ["queued", "sent", "failed", "abandoned"],
  "ansp.delivery.direct_degraded": ["queued", "sent", "failed", "abandoned"],
  "ansp.requests.state": ["received", "accepted", "declined"],
  "ansp.requests.source": ["authority", "console"],
  "ansp.adapters.kind": ["replay", "dump1090_sbs", "dump1090_json", "asterix_cat021", "atm_api"],
  "ansp.adapters.class": ["ads_b", "mode_s", "ssr", "atm_feed", "ads_l"],
  "ansp.editor.mode": ["polygon", "circle"],
  "ansp.editor.vertices": ["pair", "range"],
  "ansp.locale": ["ka", "en"],
  "ansp.login.problem": [...LOGIN_SLUGS, "other", "unavailable"],
  "ansp.picture.adapter": ["live", "stale", "disabled", "down", "unknown"],
  "ansp.picture.relevance": ["relevant", "other", "unstated"],
  "ansp.status.coordination": ["live", "connecting", "down"],
  "ansp.inbox.kind": ["intent_notice", "nonconformance", "contingent", "ended"],
  "ansp.inbox.state": ["received", "escalated", "acknowledged"],
  "ansp.inbox.filter": ["all", "escalated", "received", "acknowledged"],
  "ansp.inbox.group": ["escalated", "awaiting", "informational", "acknowledged"],
  "ansp.inbox.notify": ["unsupported", "denied", "start", "stop"],
  "ansp.policy.name": [...THRESHOLDS, "default_zone_type", "country"],
  "ansp.policy.unit": ["m", "s"],
  "ansp.policy.problem": ["number", "positive", "zone_type", "country"],
  "ansp.occurrence.channel": [...CHANNELS],
  "ansp.occurrence.category": [...CATEGORIES],
  "ansp.occurrence.aircraft": ["serial", "operator_reg", "flight_id", "authorisation_number"],
  "ansp.occurrence.problem": ["required", "enum", "icao24", "uuid", "number", "too_many", "too_long"],
};

describe("catalogues", () => {
  it("ka and en hold the same keys", () => {
    expect(Object.keys(ka).sort()).toEqual(Object.keys(en).sort());
  });

  it("a key missing from one catalogue is found", () => {
    const short: Record<string, string> = { ...ka };
    delete short["ansp.app.title"];
    expect(Object.keys(short).sort()).not.toEqual(Object.keys(en).sort());
  });

  it("no value is empty", () => {
    for (const [k, v] of [...Object.entries(ka), ...Object.entries(en)]) {
      expect(v.trim(), k).not.toBe("");
    }
  });

  it("the Georgian catalogue is Georgian", () => {
    expect(ka["ansp.app.title"]).toMatch(GEORGIAN);
    expect(en["ansp.app.title"]).not.toMatch(GEORGIAN);
    const latinOnly = Object.entries(ka).filter(([, v]) => !GEORGIAN.test(v));
    // Proper names, units and codes only (ADS-B, dump1090, v{version}, ...).
    expect(latinOnly.length).toBeLessThan(25);
  });

  it("every literal key in app/ and src/ is in both catalogues", () => {
    const files = [...sources(path.join(web, "app")), ...sources(path.join(web, "src"))];
    const keys = new Set<string>();
    for (const f of files) {
      for (const m of readFileSync(f, "utf8").matchAll(/["`](ansp\.[a-z0-9_.]+[a-z0-9_])["`]/g)) {
        if (m[1] !== undefined) keys.add(m[1]);
      }
    }
    expect(keys.size).toBeGreaterThan(100);
    const prefixes = new Set(["ansp.zone_type", "ansp.vertical_ref"]);
    const missing = [...keys].filter((k) => !prefixes.has(k) && !k.endsWith(".test") && (!present(en, k) || !present(ka, k)));
    expect(missing).toEqual([]);
  });

  it("every key built from an enumeration is in both catalogues", () => {
    const missing = Object.entries(DYNAMIC).flatMap(([prefix, values]) =>
      values.map((v) => `${prefix}.${v}`).filter((k) => !present(en, k) || !present(ka, k)),
    );
    expect(missing).toEqual([]);
  });

  it("the check finds a key that is not there", () => {
    expect(present(en, "ansp.no.such.key")).toBe(false);
    expect(present(en, "ansp.editor.vertex_count")).toBe(true);
  });
});
