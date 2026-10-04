// The manned frame reducer: ordering by captured_at (an older frame
// dropped, the same instant applied, an unordered one applied and
// counted), the snapshot, the bound, the refusal of a frame missing a
// member, and ages; each "not applied" paired with the case that applies
// (E-01).
import { describe, expect, it } from "vitest";
import type { ConsoleFrame, StatusSource } from "@rootxkit/uspace-ui/live";
import { aircraftOf, ageOf, compareShown, disabledBy, drawnOf, MannedPicture, type Aircraft } from "./manned";

function body(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    icao24: "4ca7b5",
    callsign: "TST123 ",
    position: { lat: 41.7, lng: 44.8 },
    alt_pressure_m: 1250,
    alt_wgs84_m: null,
    gs_ms: 62.5,
    track_deg: 270,
    vrate_ms: 0,
    source_class: "ads_b",
    trust: "surveillance",
    source: "ansp_feed",
    source_instance: "replay-1",
    state: "live",
    relevant: true,
    age_s: 0.4,
    ...over,
  };
}

function frame(capturedAt: string | null, over: Record<string, unknown> = {}, backlog = false): ConsoleFrame {
  return {
    schema: "track/manned/v1",
    msgId: "01K6PW0000000000000000000A",
    producer: "ansp/manned-feed",
    ts: capturedAt,
    rxTs: capturedAt ?? "2026-10-02T12:00:00.000Z",
    capturedAt,
    timeSource: "source_clock",
    backlog,
    body: body(over),
  };
}

function wire(capturedAt: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: "track/manned/v1",
    msg_id: "01K6PW0000000000000000000B",
    producer: "ansp/manned-feed",
    ts: capturedAt,
    rx_ts: capturedAt,
    captured_at: capturedAt,
    time_source: "source_clock",
    backlog: false,
    body: body(over),
  };
}

const T0 = "2026-10-02T12:00:00.000Z";
const T1 = "2026-10-02T12:00:01.000Z";
const T2 = "2026-10-02T12:00:02.000Z";

describe("aircraftOf", () => {
  it("copies the frame: both altitudes as sent, never summed", () => {
    const a = aircraftOf(frame(T0, { alt_wgs84_m: 1310 }), 1000);
    expect(a).toMatchObject({
      icao24: "4ca7b5",
      callsign: "TST123",
      altPressureM: 1250,
      altWgs84M: 1310,
      gsMs: 62.5,
      trackDeg: 270,
      state: "live",
      relevant: true,
      capturedAt: T0,
      ageSAtFrame: 0.4,
      receivedAtMs: 1000,
    });
  });

  it("refuses a frame missing a member it reads, and takes the same frame with it", () => {
    expect(aircraftOf(frame(T0, { position: undefined }), 0)).toBeNull();
    expect(aircraftOf(frame(T0, { icao24: "4CA7B5" }), 0)).toBeNull();
    expect(aircraftOf(frame(T0, { state: "lost" }), 0)).toBeNull();
    expect(aircraftOf(frame(T0, { alt_pressure_m: "1250" }), 0)).toBeNull();
    expect(aircraftOf(frame(T0, { position: { lat: 91, lng: 44 } }), 0)).toBeNull();
    expect(aircraftOf({ ...frame(T0), schema: "track/telemetry/v1" }, 0)).toBeNull();
    expect(aircraftOf(frame(null), 0)).toBeNull();
    expect(aircraftOf(frame(T0), 0)).not.toBeNull();
  });

  it("says nothing of relevance the frame did not say", () => {
    expect(aircraftOf(frame(T0, { relevant: undefined }), 0)?.relevant).toBeNull();
    expect(aircraftOf(frame(T0, { relevant: false }), 0)?.relevant).toBe(false);
  });
});

describe("MannedPicture ordering", () => {
  it("drops a frame placed before the held one, and applies a newer one", () => {
    const p = new MannedPicture();
    expect(p.apply(frame(T1, { gs_ms: 60 }), 0)).toBe("applied");
    expect(p.apply(frame(T0, { gs_ms: 10 }), 1)).toBe("out_of_order");
    expect(p.snapshot().get("4ca7b5")?.gsMs).toBe(60);
    expect(p.counters.outOfOrder).toBe(1);
    expect(p.apply(frame(T2, { gs_ms: 70 }), 2)).toBe("applied");
    expect(p.snapshot().get("4ca7b5")?.gsMs).toBe(70);
  });

  it("applies the feed's ageing at the sample's own instant: live, then stale, then source_disabled", () => {
    const p = new MannedPicture();
    p.apply(frame(T1), 0);
    expect(p.apply(frame(T1, { state: "stale", age_s: 16 }), 1)).toBe("applied");
    expect(p.snapshot().get("4ca7b5")?.state).toBe("stale");
    expect(p.apply(frame(T1, { state: "source_disabled", age_s: 17 }), 2)).toBe("applied");
    expect(p.snapshot().get("4ca7b5")?.state).toBe("source_disabled");
    expect(p.counters.outOfOrder).toBe(0);
  });

  it("applies and counts a frame whose time cannot be ordered", () => {
    const p = new MannedPicture();
    p.apply(frame(T1), 0);
    expect(p.apply(frame("2026-10-02 12:00:00", { gs_ms: 1 }), 1)).toBe("applied");
    expect(p.counters.unordered).toBe(1);
    expect(p.snapshot().get("4ca7b5")?.gsMs).toBe(1);
  });

  it("counts a refused frame and holds nothing for it", () => {
    const p = new MannedPicture();
    expect(p.apply(frame(T0, { icao24: 5 }), 0)).toBe("refused");
    expect(p.counters.refused).toBe(1);
    expect(p.snapshot().size).toBe(0);
  });

  it("keeps the snapshot map stable between changes and new after one", () => {
    const p = new MannedPicture();
    p.apply(frame(T0), 0);
    const a = p.snapshot();
    expect(p.snapshot()).toBe(a);
    p.apply(frame(T1), 1);
    expect(p.snapshot()).not.toBe(a);
  });

  it("tells its listeners of every change", () => {
    const p = new MannedPicture();
    let calls = 0;
    const off = p.subscribe(() => (calls += 1));
    p.apply(frame(T0), 0);
    off();
    p.apply(frame(T1), 1);
    expect(calls).toBe(1);
  });
});

describe("MannedPicture snapshot", () => {
  it("removes an aircraft the snapshot no longer holds and keeps one it holds", () => {
    const p = new MannedPicture();
    p.apply(frame(T0), 0);
    p.apply(frame(T0, { icao24: "4ca7b6" }), 0);
    p.replace([wire(T1)], 10);
    expect([...p.snapshot().keys()]).toEqual(["4ca7b5"]);
    expect(p.snapshot().get("4ca7b5")?.capturedAt).toBe(T1);
  });

  it("keeps a newer held sample over an older snapshot item, and takes a newer item", () => {
    const p = new MannedPicture();
    p.apply(frame(T2, { gs_ms: 99 }), 0);
    p.replace([wire(T1, { gs_ms: 1 })], 1);
    expect(p.snapshot().get("4ca7b5")?.gsMs).toBe(99);
    p.replace([wire("2026-10-02T12:00:03.000Z", { gs_ms: 2 })], 2);
    expect(p.snapshot().get("4ca7b5")?.gsMs).toBe(2);
  });

  it("an empty snapshot empties the picture; a malformed item is counted", () => {
    const p = new MannedPicture();
    p.apply(frame(T0), 0);
    p.replace([{ schema: "track/manned/v1" }], 1);
    expect(p.snapshot().size).toBe(0);
    expect(p.counters.refused).toBe(1);
  });
});

describe("MannedPicture bound (E-10)", () => {
  it("evicts the least recently received past the bound, and evicts nothing at it", () => {
    const p = new MannedPicture(2);
    p.apply(frame(T0, { icao24: "000001" }), 0);
    p.apply(frame(T0, { icao24: "000002" }), 1);
    expect(p.counters.evicted).toBe(0);
    p.apply(frame(T1, { icao24: "000001" }), 2);
    p.apply(frame(T0, { icao24: "000003" }), 3);
    expect([...p.snapshot().keys()].sort()).toEqual(["000001", "000003"]);
    expect(p.counters.evicted).toBe(1);
  });
});

function held(over: Partial<Aircraft> = {}): Aircraft {
  const a = aircraftOf(frame(T0), 10_000);
  if (a === null) throw new Error("fixture");
  return { ...a, ...over };
}

describe("ages", () => {
  it("counts the frame's age on from its receipt", () => {
    expect(ageOf(held({ ageSAtFrame: 2 }), 13_000, null)).toBeCloseTo(5);
  });

  it("without age_s, reads captured_at on the server's clock, and says nothing without the offset", () => {
    const a = held({ ageSAtFrame: null });
    const nowMs = Date.parse(T0) + 4000;
    expect(ageOf(a, nowMs, 0)).toBeCloseTo(4);
    expect(ageOf(a, nowMs, 1000)).toBeCloseTo(5);
    expect(ageOf(a, nowMs, null)).toBeNull();
  });

  it("draws a live aircraft stale once its age reaches stale_after_s, and live below it", () => {
    const a = held({ ageSAtFrame: 0 });
    expect(drawnOf(a, 10_000 + 14_000, 15, null)).toMatchObject({ state: "live", agedHere: false });
    expect(drawnOf(a, 10_000 + 15_000, 15, null)).toMatchObject({ state: "stale", agedHere: true });
  });

  it("ages nothing without a threshold from the status frame", () => {
    const a = held({ ageSAtFrame: 0 });
    expect(drawnOf(a, 10_000 + 3_600_000, null, null).state).toBe("live");
  });

  it("keeps the feed's stale and source_disabled whatever the age", () => {
    expect(drawnOf(held({ state: "stale" }), 10_000, 15, null).state).toBe("stale");
    expect(drawnOf(held({ state: "source_disabled" }), 10_000, 15, null).state).toBe("source_disabled");
  });

  it("draws a backlog sample as backlog while it is young, and live without the flag", () => {
    expect(drawnOf(held({ backlog: true, ageSAtFrame: 0 }), 10_000, 15, null).state).toBe("backlog");
    expect(drawnOf(held({ backlog: false, ageSAtFrame: 0 }), 10_000, 15, null).state).toBe("live");
  });
});

function source(over: Partial<StatusSource>): StatusSource {
  return {
    source: "ansp_feed",
    sourceInstance: "sbs-1",
    state: "live",
    since: T0,
    ageS: 1,
    disabledBy: null,
    disabledByWho: null,
    counters: { accepted: 1, refused: 0 },
    lagS: null,
    ...over,
  };
}

describe("disabledBy", () => {
  it("names who disabled the adapter, its own switch before the type's", () => {
    const sources = [
      source({ sourceInstance: null, state: "disabled", disabledBy: "type", disabledByWho: "admin-type" }),
      source({ state: "disabled", disabledBy: "instance", disabledByWho: "admin" }),
    ];
    expect(disabledBy("sbs-1", sources)).toEqual({ by: "instance", who: "admin" });
    expect(disabledBy("replay-1", sources)).toEqual({ by: "type", who: "admin-type" });
  });

  it("is null when no source of it says disabled", () => {
    expect(disabledBy("sbs-1", [source({})])).toBeNull();
  });
});

describe("compareShown", () => {
  it("puts relevant aircraft first, then by state", () => {
    const live = { a: held({ relevant: false }), d: { state: "live" as const, ageS: 0, agedHere: false } };
    const relevantStale = { a: held({ relevant: true, icao24: "000002" }), d: { state: "stale" as const, ageS: 20, agedHere: false } };
    const disabled = { a: held({ relevant: false, icao24: "000003" }), d: { state: "source_disabled" as const, ageS: 20, agedHere: false } };
    expect([disabled, live, relevantStale].sort(compareShown)).toEqual([relevantStale, live, disabled]);
  });
});
