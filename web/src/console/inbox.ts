// The coordination inbox as the console holds it (2021/664 Art. 13(2),
// Annex V; 01 N3): GET /v1/coordination/inbox, then every
// coordination/notice/v1 frame of WS /v1/coordination/stream on top (the
// body is the inbox item, api/openapi.yaml CoordinationNotice; docs/
// PLAN.md section 15 row 24). Copying, not judging: a frame replaces the
// notice it names unless the console holds a later state of it (an
// acknowledged notice never goes back to escalated, an escalation never
// goes back to an earlier count), and the restrictions a notice touches
// are the API's (restriction_ids, computed at receipt), never worked out
// here. The volumes are drawn as the USSP sent them: an outline polygon
// as its vertices, an outline circle as its centre (drawing a radius
// would be geodesy, T12).
import type { ConsoleFrame } from "@rootxkit/uspace-ui/live";
import type { components } from "../api/types";

export type ApiNotice = components["schemas"]["CoordinationNotice"];

/** The schema of an inbox frame (coordination/notice/v1). */
export const NOTICE_SCHEMA = "coordination/notice/v1";

const KINDS: ReadonlySet<string> = new Set(["intent_notice", "nonconformance", "contingent", "ended"]);
const STATES: ReadonlySet<string> = new Set(["received", "acknowledged", "escalated"]);

/** The largest note the API takes (coord.MaxNoteBytes: UTF-8 bytes, not characters). */
export const NOTE_MAX_BYTES = 500;

function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function strings(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

/**
 * The inbox item of a coordination/notice/v1 frame, or null when the
 * frame is another schema or lacks a member the console reads (never
 * applied in part).
 */
export function noticeOf(frame: ConsoleFrame): ApiNotice | null {
  if (frame.schema !== NOTICE_SCHEMA) return null;
  const b = obj(frame.body);
  if (b === null) return null;
  for (const k of ["ack_id", "sender_client_id", "ussp_id", "notice_ref", "received_at"]) {
    if (typeof b[k] !== "string" || b[k] === "") return null;
  }
  if (typeof b["kind"] !== "string" || !KINDS.has(b["kind"])) return null;
  if (typeof b["state"] !== "string" || !STATES.has(b["state"])) return null;
  if (!strings(b["intent_refs"]) || !strings(b["authorisation_numbers"])) return null;
  if (b["escalations"] !== undefined && (typeof b["escalations"] !== "number" || b["escalations"] < 0)) return null;
  if (b["restriction_ids"] !== undefined && !strings(b["restriction_ids"])) return null;
  return b as unknown as ApiNotice;
}

/** Whether `next` is a later state of the notice than `held`. */
export function isLater(held: ApiNotice, next: ApiNotice): boolean {
  if (held.state === "acknowledged") return next.state === "acknowledged" && (next.acknowledged_at ?? "") >= (held.acknowledged_at ?? "");
  if (next.state === "acknowledged") return true;
  return (next.escalations ?? 0) >= (held.escalations ?? 0);
}

/** `incoming` merged into `held` by ack_id: a later state replaces, an earlier one is dropped. */
export function mergeNotices(held: ReadonlyMap<string, ApiNotice>, incoming: readonly ApiNotice[]): { notices: Map<string, ApiNotice>; dropped: number } {
  const out = new Map(held);
  let dropped = 0;
  for (const n of incoming) {
    const cur = out.get(n.ack_id);
    if (cur === undefined || isLater(cur, n)) out.set(n.ack_id, n);
    else dropped += 1;
  }
  return { notices: out, dropped };
}

/**
 * The notices the console holds after a fresh read of the inbox
 * (`fetched`, the API's list): the list itself, each notice at the later
 * of its listed and held states, plus the held notices the stream
 * brought (`touched`) while the list was being read, which the list may
 * predate. A held notice the API no longer lists and the stream did not
 * bring is dropped: the API's list is the inbox, and what it pruned is
 * not kept here for ever.
 */
export function reconcileNotices(held: ReadonlyMap<string, ApiNotice>, fetched: readonly ApiNotice[], touched: ReadonlySet<string>): Map<string, ApiNotice> {
  const base = mergeNotices(new Map(), fetched).notices;
  const carried: ApiNotice[] = [];
  for (const [id, n] of held) {
    if (base.has(id) || touched.has(id)) carried.push(n);
  }
  return mergeNotices(base, carried).notices;
}

/**
 * `notices` held to at most `max`: past it the settled notices go first,
 * the acknowledged ones oldest acknowledgement first, then the
 * informational ones oldest receipt first, each counted in `evicted`. A
 * notice that awaits a person (escalated, or received and requiring an
 * acknowledgement) is never evicted, even past the bound: nothing hides
 * a notice someone must act on.
 */
export function boundNotices(notices: ReadonlyMap<string, ApiNotice>, max: number): { notices: Map<string, ApiNotice>; evicted: number } {
  const out = new Map(notices);
  if (out.size <= max) return { notices: out, evicted: 0 };
  const settled = [...out.values()]
    .filter((n) => {
      const g = groupOf(n);
      return g === "acknowledged" || g === "informational";
    })
    .sort((a, b) => {
      const ga = groupOf(a) === "acknowledged" ? 0 : 1;
      const gb = groupOf(b) === "acknowledged" ? 0 : 1;
      if (ga !== gb) return ga - gb;
      return ga === 0 ? (a.acknowledged_at ?? "").localeCompare(b.acknowledged_at ?? "") : a.received_at.localeCompare(b.received_at);
    });
  let evicted = 0;
  for (const n of settled) {
    if (out.size <= max) break;
    out.delete(n.ack_id);
    evicted += 1;
  }
  return { notices: out, evicted };
}

/** Whether a notice frame is news of an escalation (for the opt-in browser notification). */
export function escalationNews(held: ApiNotice | undefined, next: ApiNotice): boolean {
  if (next.state !== "escalated") return false;
  if (held === undefined || held.state !== "escalated") return held?.state !== "acknowledged";
  return (next.escalations ?? 0) > (held.escalations ?? 0);
}

/** The group a notice is listed in. */
export type Group = "escalated" | "awaiting" | "informational" | "acknowledged";

export function groupOf(n: ApiNotice): Group {
  if (n.state === "acknowledged") return "acknowledged";
  if (n.state === "escalated") return "escalated";
  return n.acknowledgement_required === true ? "awaiting" : "informational";
}

export const GROUP_ORDER: readonly Group[] = ["escalated", "awaiting", "informational", "acknowledged"];

/**
 * The inbox in the order it is shown: escalated first (the longest
 * waiting on top), then the ones awaiting an acknowledgement (oldest
 * first), then the informational ones and the acknowledged ones (newest
 * first).
 */
export function ordered(notices: Iterable<ApiNotice>): ApiNotice[] {
  const rank = (n: ApiNotice) => GROUP_ORDER.indexOf(groupOf(n));
  return [...notices].sort((a, b) => {
    const r = rank(a) - rank(b);
    if (r !== 0) return r;
    const g = groupOf(a);
    if (g === "escalated" || g === "awaiting") return a.received_at.localeCompare(b.received_at);
    if (g === "acknowledged") return (b.acknowledged_at ?? "").localeCompare(a.acknowledged_at ?? "");
    return b.received_at.localeCompare(a.received_at);
  });
}

/** The notices awaiting a person: escalated, and received ones that require it. */
export function awaitingCount(notices: Iterable<ApiNotice>): { escalated: number; awaiting: number } {
  let escalated = 0;
  let awaiting = 0;
  for (const n of notices) {
    const g = groupOf(n);
    if (g === "escalated") escalated += 1;
    else if (g === "awaiting") awaiting += 1;
  }
  return { escalated, awaiting };
}

/** One intent of a notice's payload, as the USSP sent it. */
export interface IntentLine {
  intentRef: string;
  authorisationNumber: string;
  state: string;
  timeStart: string;
  timeEnd: string;
}

/** The intents of a notice's payload (coordination/annex_v/v1), the malformed ones left out and counted. */
export function intentsOf(payload: unknown): { intents: IntentLine[]; malformed: number } {
  const p = obj(payload);
  const raw = p?.["intents"];
  if (!Array.isArray(raw)) return { intents: [], malformed: 0 };
  const intents: IntentLine[] = [];
  let malformed = 0;
  for (const item of raw) {
    const i = obj(item);
    const fields = ["intent_ref", "authorisation_number", "state", "time_start", "time_end"] as const;
    if (i === null || fields.some((f) => typeof i[f] !== "string")) {
      malformed += 1;
      continue;
    }
    intents.push({
      intentRef: i["intent_ref"] as string,
      authorisationNumber: i["authorisation_number"] as string,
      state: i["state"] as string,
      timeStart: i["time_start"] as string,
      timeEnd: i["time_end"] as string,
    });
  }
  return { intents, malformed };
}

function latLng(v: unknown): [number, number] | null {
  const o = obj(v);
  if (o === null) return null;
  const lat = o["lat"];
  const lng = o["lng"];
  if (typeof lat !== "number" || typeof lng !== "number" || !Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  if (lat < -90 || lat > 90 || lng < -180 || lng > 180) return null;
  return [lng, lat];
}

function altitude(v: unknown): number | null {
  const o = obj(v);
  const value = o?.["value"];
  return o !== null && o["reference"] === "W84" && typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** The volumes of a notice's intents as map features, copied (a circle is its centre). */
export function volumesOf(ackId: string, payload: unknown, emphasised: boolean): { features: GeoJSON.Feature[]; circles: number; malformed: number } {
  const p = obj(payload);
  const features: GeoJSON.Feature[] = [];
  let circles = 0;
  let malformed = 0;
  const intents = Array.isArray(p?.["intents"]) ? (p["intents"] as unknown[]) : [];
  for (const item of intents) {
    const i = obj(item);
    const vols = Array.isArray(i?.["volumes"]) ? (i["volumes"] as unknown[]) : [];
    for (const v4 of vols) {
      const vol = obj(obj(v4)?.["volume"]);
      const properties = {
        ack_id: ackId,
        intent_ref: typeof i?.["intent_ref"] === "string" ? i["intent_ref"] : "",
        lower_w84_m: altitude(vol?.["altitude_lower"]),
        upper_w84_m: altitude(vol?.["altitude_upper"]),
        emphasised,
      };
      const poly = obj(vol?.["outline_polygon"]);
      const circle = obj(vol?.["outline_circle"]);
      if (poly !== null && Array.isArray(poly["vertices"])) {
        const ring = (poly["vertices"] as unknown[]).map(latLng);
        if (ring.length < 3 || ring.some((x) => x === null)) {
          malformed += 1;
          continue;
        }
        const closed = ring as [number, number][];
        const first = closed[0] as [number, number];
        features.push({ type: "Feature", properties, geometry: { type: "Polygon", coordinates: [[...closed, [first[0], first[1]]]] } });
      } else if (circle !== null && latLng(circle["center"]) !== null) {
        circles += 1;
        features.push({ type: "Feature", properties: { ...properties, circle: true }, geometry: { type: "Point", coordinates: latLng(circle["center"]) as [number, number] } });
      } else {
        malformed += 1;
      }
    }
  }
  return { features, circles, malformed };
}

/** The UTF-8 length of a note (the API bounds bytes, coord.MaxNoteBytes). */
export function noteBytes(note: string): number {
  return new TextEncoder().encode(note.trim()).length;
}

/** The acknowledgement body: the note when there is one (AcknowledgeRequest). */
export function acknowledgeBody(note: string): { note?: string } {
  const n = note.trim();
  return n === "" ? {} : { note: n };
}
