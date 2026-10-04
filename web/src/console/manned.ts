// The manned picture as the console holds it: every track/manned/v1
// frame of WS /v1/manned-traffic/stream (api/openapi.yaml MannedTrack)
// and every console/snapshot/v1 manned[] item, by icao24, copied as the
// feed sent it. Nothing is judged and nothing is computed from a
// position or an altitude: an aircraft is drawn at its last position with
// its age, never extrapolated (LESSONS B-13); pressure altitude and WGS84
// height are kept apart and never summed or converted (CLAUDE.md rule 9).
//
// Ordering (T-13): a frame placed before the held one (captured_at) is
// dropped and counted; a frame placed at the same instant is applied,
// because manned-feed sends an aircraft's ageing (stale, source_disabled)
// with the sample's own times, never restamped. A frame whose time cannot
// be ordered against the held one is applied and counted. Past
// `maxAircraft` the least recently received aircraft is evicted and
// counted (E-10); manned-feed's own picture is bounded the same way.
import { compareCapturedAt, parseFrame, utcMs, type ConsoleFrame, type StatusSource } from "@rootxkit/uspace-ui/live";
import type { components } from "../api/types";

export type ApiMannedTrack = components["schemas"]["MannedTrack"];
export type ApiAdapterState = components["schemas"]["AdapterState"];

/** The schema of a manned aircraft frame (04 §3.1). */
export const MANNED_SCHEMA = "track/manned/v1";

/**
 * Aircraft this console holds; past it the least recently received is
 * evicted and counted. A display bound, the order of manned-feed's own
 * picture bound (picture.DefaultLimits, 5000); not a threshold.
 */
export const MAX_AIRCRAFT = 5000;

/** The feed's states of an aircraft (MannedTrack.state). */
export type FeedState = ApiMannedTrack["state"];
const FEED_STATES: ReadonlySet<string> = new Set(["live", "stale", "source_disabled"]);

/** One aircraft as the last applied frame said it. */
export interface Aircraft {
  icao24: string;
  callsign: string | null;
  lat: number;
  lng: number;
  /** Pressure altitude (ISA 1013.25 hPa), as sent; never AMSL. */
  altPressureM: number | null;
  /** Height above the WGS84 ellipsoid, as sent, when the feed has it. */
  altWgs84M: number | null;
  gsMs: number | null;
  trackDeg: number | null;
  vrateMs: number | null;
  emergency: boolean | null;
  squawk: string | null;
  sourceInstance: string;
  sourceClass: string;
  state: FeedState;
  /** Inside a U-space volume plus the policy margin; null when the frame did not say. */
  relevant: boolean | null;
  /** The envelope's backlog flag: delivered late, as recorded (T-04). */
  backlog: boolean;
  capturedAt: string;
  /** The frame's age_s (seconds since captured_at when manned-feed wrote it). */
  ageSAtFrame: number | null;
  /** Browser clock of the frame's receipt. */
  receivedAtMs: number;
}

export interface PictureCounters {
  /** A frame of track/manned/v1 that lacked a member the console reads. */
  refused: number;
  /** A frame placed before the held one: dropped (T-13). */
  outOfOrder: number;
  /** A frame whose time could not be ordered against the held one: applied. */
  unordered: number;
  /** An aircraft pushed out by the bound (E-10). */
  evicted: number;
}

function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function numOrNull(v: unknown): number | null | undefined {
  if (v === null || v === undefined) return null;
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function strOrNull(v: unknown): string | null | undefined {
  if (v === null || v === undefined) return null;
  return typeof v === "string" ? v : undefined;
}

const ICAO24 = /^[0-9a-f]{6}$/;

/**
 * The aircraft a track/manned/v1 frame carries, or null when the frame is
 * another schema or lacks a member the console reads (never applied in
 * part). Copies, never converts.
 */
export function aircraftOf(frame: ConsoleFrame, receivedAtMs: number): Aircraft | null {
  if (frame.schema !== MANNED_SCHEMA || frame.capturedAt === null) return null;
  const b = obj(frame.body);
  if (b === null) return null;
  const pos = obj(b["position"]);
  const icao24 = b["icao24"];
  if (typeof icao24 !== "string" || !ICAO24.test(icao24) || pos === null) return null;
  const lat = pos["lat"];
  const lng = pos["lng"];
  if (typeof lat !== "number" || typeof lng !== "number" || !Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  if (lat < -90 || lat > 90 || lng < -180 || lng > 180) return null;
  const state = b["state"];
  if (typeof state !== "string" || !FEED_STATES.has(state)) return null;
  const sourceInstance = b["source_instance"];
  const sourceClass = b["source_class"];
  if (typeof sourceInstance !== "string" || sourceInstance === "" || typeof sourceClass !== "string") return null;
  const altPressureM = numOrNull(b["alt_pressure_m"]);
  const altWgs84M = numOrNull(b["alt_wgs84_m"]);
  const gsMs = numOrNull(b["gs_ms"]);
  const trackDeg = numOrNull(b["track_deg"]);
  const vrateMs = numOrNull(b["vrate_ms"]);
  const ageS = numOrNull(b["age_s"]);
  const callsign = strOrNull(b["callsign"]);
  const squawk = strOrNull(b["squawk"]);
  const emergency = b["emergency"];
  const relevant = b["relevant"];
  if (
    altPressureM === undefined ||
    altWgs84M === undefined ||
    gsMs === undefined ||
    trackDeg === undefined ||
    vrateMs === undefined ||
    ageS === undefined ||
    callsign === undefined ||
    squawk === undefined
  ) {
    return null;
  }
  if (emergency !== undefined && emergency !== null && typeof emergency !== "boolean") return null;
  if (relevant !== undefined && typeof relevant !== "boolean") return null;
  return {
    icao24,
    callsign: callsign === null || callsign.trim() === "" ? null : callsign.trim(),
    lat,
    lng,
    altPressureM,
    altWgs84M,
    gsMs,
    trackDeg,
    vrateMs,
    emergency: typeof emergency === "boolean" ? emergency : null,
    squawk,
    sourceInstance,
    sourceClass,
    state: state as FeedState,
    relevant: typeof relevant === "boolean" ? relevant : null,
    backlog: frame.backlog,
    capturedAt: frame.capturedAt,
    ageSAtFrame: ageS !== null && ageS >= 0 ? ageS : null,
    receivedAtMs,
  };
}

export type Applied = "applied" | "refused" | "out_of_order";

/**
 * The console's picture: a mutable map behind a snapshot that is stable
 * between changes (for useSyncExternalStore), and its counters.
 */
export class MannedPicture {
  private readonly held = new Map<string, Aircraft>();
  private view: ReadonlyMap<string, Aircraft> = new Map();
  private dirty = false;
  private readonly listeners = new Set<() => void>();
  readonly counters: PictureCounters = { refused: 0, outOfOrder: 0, unordered: 0, evicted: 0 };

  constructor(private readonly maxAircraft: number = MAX_AIRCRAFT) {}

  /** One frame of the stream. */
  apply(frame: ConsoleFrame, receivedAtMs: number): Applied {
    const a = aircraftOf(frame, receivedAtMs);
    if (a === null) {
      this.counters.refused += 1;
      this.changed();
      return "refused";
    }
    const r = this.put(a);
    this.changed();
    return r;
  }

  /**
   * A console/snapshot/v1's manned[] (each item a complete frame): the
   * feed's picture on (re)connect and on every subscribe. A held aircraft
   * absent from it is gone from the feed's picture (evicted there after
   * its last sample) and is removed here; one present is updated unless
   * the console holds a newer sample of it.
   */
  replace(items: readonly unknown[], receivedAtMs: number): void {
    const present = new Set<string>();
    for (const raw of items) {
      const frame = parseFrame(raw);
      const a = frame === null ? null : aircraftOf(frame, receivedAtMs);
      if (a === null) {
        this.counters.refused += 1;
        continue;
      }
      present.add(a.icao24);
      this.put(a);
    }
    for (const id of [...this.held.keys()]) if (!present.has(id)) this.held.delete(id);
    this.changed();
  }

  private put(a: Aircraft): Applied {
    const cur = this.held.get(a.icao24);
    if (cur !== undefined) {
      const order = compareCapturedAt(a.capturedAt, cur.capturedAt);
      if (order === null) this.counters.unordered += 1;
      else if (order < 0) {
        this.counters.outOfOrder += 1;
        return "out_of_order";
      }
      // Re-inserted so the map's order is the order of receipt.
      this.held.delete(a.icao24);
    }
    this.held.set(a.icao24, a);
    while (this.held.size > this.maxAircraft) {
      const oldest = this.held.keys().next();
      if (oldest.done === true) break;
      this.held.delete(oldest.value);
      this.counters.evicted += 1;
    }
    return "applied";
  }

  private changed(): void {
    this.dirty = true;
    for (const l of this.listeners) l();
  }

  /** A map stable between changes. */
  snapshot = (): ReadonlyMap<string, Aircraft> => {
    if (this.dirty) {
      this.view = new Map(this.held);
      this.dirty = false;
    }
    return this.view;
  };

  subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn);
    return () => {
      this.listeners.delete(fn);
    };
  };
}

/** What an aircraft is drawn as. */
export type DrawnState = "live" | "backlog" | "stale" | "source_disabled";

export interface Drawn {
  state: DrawnState;
  /** Seconds since captured_at on the feed's clock, counted on; null when not known. */
  ageS: number | null;
  /** Stale because its age passed the status frame's stale_after_s before the feed said so. */
  agedHere: boolean;
}

/**
 * The age of an aircraft now: the frame's age_s counted on by the browser
 * clock since its receipt, or, without age_s, the age of captured_at on
 * the server's clock (`clockOffsetMs`, server minus browser, from the
 * status frame). Null when neither can be read: an age is never guessed.
 */
export function ageOf(a: Aircraft, nowMs: number, clockOffsetMs: number | null): number | null {
  if (a.ageSAtFrame !== null) {
    const age = a.ageSAtFrame + Math.max(0, nowMs - a.receivedAtMs) / 1000;
    return Number.isFinite(age) ? age : null;
  }
  const captured = utcMs(a.capturedAt);
  if (captured === null || clockOffsetMs === null) return null;
  const age = (nowMs + clockOffsetMs - captured) / 1000;
  return Number.isFinite(age) ? Math.max(0, age) : null;
}

/**
 * How an aircraft is drawn now. source_disabled and stale are the feed's;
 * an aircraft the feed still calls live is drawn stale once its age
 * reaches the status frame's stale_after_s (the stream may have stopped
 * saying anything). Without that threshold (no valid status frame yet)
 * nothing is aged here: the console never fills a threshold in (INV-03).
 */
export function drawnOf(a: Aircraft, nowMs: number, staleAfterS: number | null, clockOffsetMs: number | null): Drawn {
  const ageS = ageOf(a, nowMs, clockOffsetMs);
  if (a.state === "source_disabled") return { state: "source_disabled", ageS, agedHere: false };
  if (a.state === "stale") return { state: "stale", ageS, agedHere: false };
  if (staleAfterS !== null && ageS !== null && ageS >= staleAfterS) return { state: "stale", ageS, agedHere: true };
  return { state: a.backlog ? "backlog" : "live", ageS, agedHere: false };
}

/** The switch that disabled an adapter, from the status frame's sources[] (B-11). */
export interface DisabledBy {
  /** type, instance or default_deny; null when the source said disabled without one. */
  by: string | null;
  /** Who set the switch; null when the feed does not say. */
  who: string | null;
}

/** The source class of every manned adapter and track (MannedTrack.source). */
export const MANNED_SOURCE: ApiMannedTrack["source"] = "ansp_feed";

/**
 * Who disabled the adapter `instance`: its own source/status/v1 in the
 * status frame's sources[], else the type's (source_instance null), both
 * of the manned feed's source class only: another class's switch (a
 * Remote ID type switch, an instance of the same name under another
 * class) never names who disabled a manned adapter. Null when no source
 * of it says disabled.
 */
export function disabledBy(instance: string, sources: readonly StatusSource[]): DisabledBy | null {
  const mine = sources.filter((s) => s.source === MANNED_SOURCE && s.state === "disabled");
  const own = mine.find((s) => s.sourceInstance === instance);
  const hit = own ?? mine.find((s) => s.sourceInstance === null);
  if (hit === undefined) return null;
  return { by: hit.disabledBy, who: hit.disabledByWho };
}

/** The drawing order: relevant first, then live, backlog, stale, disabled; then by identity. */
const STATE_ORDER: Record<DrawnState, number> = { live: 0, backlog: 1, stale: 2, source_disabled: 3 };

export function compareShown(x: { a: Aircraft; d: Drawn }, y: { a: Aircraft; d: Drawn }): number {
  const rx = x.a.relevant === true ? 0 : 1;
  const ry = y.a.relevant === true ? 0 : 1;
  if (rx !== ry) return rx - ry;
  const sx = STATE_ORDER[x.d.state];
  const sy = STATE_ORDER[y.d.state];
  if (sx !== sy) return sx - sy;
  const nx = x.a.callsign ?? x.a.icao24;
  const ny = y.a.callsign ?? y.a.icao24;
  return nx.localeCompare(ny);
}
