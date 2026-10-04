// The picture's words: both altitudes each with its datum (never one for
// the other, never summed), the state with its age, and who disabled a
// source; the adapters line of the empty picture (SC-22).
import { describe, expect, it } from "vitest";
import { createTranslator } from "@rootxkit/uspace-ui/i18n";
import type { StatusSource } from "@rootxkit/uspace-ui/live";
import { catalogues } from "../i18n/catalogues";
import type { Aircraft, Drawn } from "./manned";
import { adaptersLine, altitudeText, identText, LabelCache, labelText, stateText, symbolOf } from "./picture";

const t = createTranslator("en", catalogues);

const A: Aircraft = {
  icao24: "4ca7b5",
  callsign: "TST123",
  lat: 41.7,
  lng: 44.8,
  altPressureM: 1250,
  altWgs84M: null,
  gsMs: 62.5,
  trackDeg: 270,
  vrateMs: 0,
  emergency: null,
  squawk: null,
  sourceInstance: "sbs-1",
  sourceClass: "ads_b",
  state: "live",
  relevant: true,
  backlog: false,
  capturedAt: "2026-10-02T12:00:00.000Z",
  ageSAtFrame: 1,
  receivedAtMs: 0,
};

const disabled: StatusSource = {
  source: "ansp_feed",
  sourceInstance: "sbs-1",
  state: "disabled",
  since: "2026-10-02T11:00:00.000Z",
  ageS: 60,
  disabledBy: "instance",
  disabledByWho: "admin",
  counters: { accepted: 0, refused: 2 },
  lagS: null,
};

function drawn(state: Drawn["state"], ageS: number | null = 3, agedHere = false): Drawn {
  return { state, ageS, agedHere };
}

describe("picture words", () => {
  it("names the aircraft by callsign and address", () => {
    expect(identText(A)).toBe("TST123 · 4ca7b5");
    expect(identText({ ...A, callsign: null })).toBe("4ca7b5");
  });

  it("labels pressure altitude as pressure altitude and adds WGS84 only when sent", () => {
    expect(altitudeText(A, t, "en")).toMatch(/1[ ,]?250 m pressure altitude$/);
    const both = altitudeText({ ...A, altWgs84M: 1310 }, t, "en");
    expect(both).toMatch(/pressure altitude · 1[ ,]?310 m above the WGS84 ellipsoid$/);
    expect(both).not.toMatch(/AMSL/);
    expect(altitudeText({ ...A, altPressureM: null }, t, "en")).toBe("altitude not reported");
  });

  it("states live, stale and disabled with the age, and who disabled the source", () => {
    expect(stateText(A, drawn("live"), [], 15, t, "en")).toBe("Live, age 3 s");
    expect(stateText(A, drawn("stale", 20), [], 15, t, "en")).toBe("Stale (20 s)");
    expect(stateText(A, drawn("stale", 20, true), [], 15, t, "en")).toBe("Stale (20 s): nothing newer within 15 s");
    expect(stateText(A, drawn("source_disabled", 20), [disabled], 15, t, "en")).toBe("Source sbs-1 disabled by admin (20 s)");
    expect(stateText(A, drawn("source_disabled", 20), [], 15, t, "en")).toContain("does not say by whom");
    expect(stateText(A, drawn("live", null), [], 15, t, "en")).toBe("Live, age age unknown");
  });

  it("puts every part on the map label, one per line", () => {
    expect(labelText(A, drawn("live"), [], 15, t, "en").split("\n")).toHaveLength(4);
  });

  it("names the symbol by state and relevance", () => {
    expect(symbolOf(A, drawn("stale"))).toBe("stale-relevant");
    expect(symbolOf({ relevant: false }, drawn("live"))).toBe("live-other");
    expect(symbolOf({ relevant: null }, drawn("source_disabled"))).toBe("source_disabled-unstated");
  });

  it("says every adapter's state on the empty picture, and says when there is none", () => {
    const line = adaptersLine(
      {
        adapters: [
          { id: "replay-1", state: "live", enabled: true, age_s: 1 },
          { id: "sbs-1", state: "disabled", enabled: false, age_s: null },
        ],
        sources: [disabled],
      },
      t,
      "en",
    );
    expect(line).toBe("replay-1: live, last frame 1 s ago; sbs-1: disabled by admin");
    expect(adaptersLine({ adapters: [], sources: [] }, t, "en")).toBe("no adapter reported");
    expect(adaptersLine({ adapters: null, sources: [] }, t, "en")).toBe("no adapter reported");
  });
});

describe("LabelCache", () => {
  const d: Drawn = { state: "live", ageS: 1, agedHere: false };

  function counting() {
    let n = 0;
    const build = (a: Aircraft, dd: Drawn) => {
      n += 1;
      return `${a.icao24} ${dd.state} ${dd.ageS ?? "-"} #${n}`;
    };
    return { build, calls: () => n };
  }

  it("rebuilds a label at most once per refresh for an unchanged aircraft as its age ticks", () => {
    const c = new LabelCache(5000);
    const b = counting();
    const first = c.labels([{ a: A, d }], 0, "g", b.build);
    for (let ms = 1000; ms < 5000; ms += 1000) {
      expect(c.labels([{ a: A, d: { ...d, ageS: 1 + ms / 1000 } }], ms, "g", b.build)).toEqual(first);
    }
    expect(b.calls()).toBe(1);
    const refreshed = c.labels([{ a: A, d: { ...d, ageS: 6 } }], 5000, "g", b.build);
    expect(b.calls()).toBe(2);
    expect(refreshed[0]).toContain(" 6 ");
  });

  it("rebuilds at once on a new frame, a new drawn state or a new generation", () => {
    const c = new LabelCache(5000);
    const b = counting();
    c.labels([{ a: A, d }], 0, "g", b.build);
    c.labels([{ a: { ...A, lat: 41.8 }, d }], 100, "g", b.build);
    expect(b.calls()).toBe(2);
    const moved = { ...A, lat: 41.8 };
    c.labels([{ a: moved, d }], 200, "g", b.build);
    c.labels([{ a: moved, d: { state: "stale", ageS: 20, agedHere: true } }], 300, "g", b.build);
    expect(b.calls()).toBe(4);
    c.labels([{ a: moved, d: { state: "stale", ageS: 20, agedHere: true } }], 400, "g2", b.build);
    expect(b.calls()).toBe(5);
  });

  it("forgets the aircraft a pass no longer holds (bounded by the picture)", () => {
    const c = new LabelCache(5000);
    const b = counting();
    const B = { ...A, icao24: "000001" };
    c.labels([{ a: A, d }, { a: B, d }], 0, "g", b.build);
    expect(c.size).toBe(2);
    c.labels([{ a: A, d }], 100, "g", b.build);
    expect(c.size).toBe(1);
    c.labels([{ a: A, d }, { a: B, d }], 200, "g", b.build);
    expect(b.calls()).toBe(3);
  });
});
