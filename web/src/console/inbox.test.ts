// The inbox as the console holds it: a frame read only when whole, a
// later state replacing an earlier one and never the reverse, escalated
// notices first, escalation news for the opt-in notification, the
// intents and volumes copied from the payload, the note bounded in bytes
// (E-01 pairs throughout).
import { describe, expect, it } from "vitest";
import type { ConsoleFrame } from "@rootxkit/uspace-ui/live";
import {
  acknowledgeBody,
  boundNotices,
  awaitingCount,
  escalationNews,
  groupOf,
  intentsOf,
  isLater,
  mergeNotices,
  noteBytes,
  noticeOf,
  ordered,
  reconcileNotices,
  volumesOf,
  type ApiNotice,
} from "./inbox";

function notice(over: Partial<ApiNotice> = {}): ApiNotice {
  return {
    ack_id: "01K6P0N0000000000000000001",
    kind: "nonconformance",
    sender_client_id: "ussp-alpha-01",
    ussp_id: "alpha",
    notice_ref: "nc-1",
    intent_refs: ["2f8343be-6482-4d1b-a474-16847e01af1e"],
    authorisation_numbers: ["GEO-AUTH-1"],
    received_at: "2026-10-02T12:00:00.000Z",
    state: "received",
    acknowledgement_required: true,
    escalations: 0,
    ...over,
  };
}

function frame(body: unknown, schema = "coordination/notice/v1"): ConsoleFrame {
  return {
    schema,
    msgId: "01K6PW0000000000000000000A",
    producer: "ansp/api",
    ts: null,
    rxTs: "2026-10-02T12:00:00.000Z",
    capturedAt: "2026-10-02T12:00:00.000Z",
    timeSource: "system",
    backlog: false,
    body,
  };
}

describe("noticeOf", () => {
  it("reads a whole inbox item, and refuses one missing a member", () => {
    expect(noticeOf(frame(notice()))?.ack_id).toBe("01K6P0N0000000000000000001");
    expect(noticeOf(frame({ ...notice(), kind: "other" }))).toBeNull();
    expect(noticeOf(frame({ ...notice(), state: "lost" }))).toBeNull();
    expect(noticeOf(frame({ ...notice(), intent_refs: "x" }))).toBeNull();
    expect(noticeOf(frame({ ...notice(), ack_id: "" }))).toBeNull();
    expect(noticeOf(frame({ ...notice(), escalations: -1 }))).toBeNull();
    expect(noticeOf(frame(notice(), "restriction/state/v1"))).toBeNull();
  });
});

describe("merge", () => {
  it("replaces with a later escalation and keeps a later one over an earlier frame", () => {
    const held = new Map([[notice().ack_id, notice({ state: "escalated", escalations: 2 })]]);
    const earlier = mergeNotices(held, [notice({ state: "escalated", escalations: 1 })]);
    expect(earlier.notices.get(notice().ack_id)?.escalations).toBe(2);
    expect(earlier.dropped).toBe(1);
    const later = mergeNotices(held, [notice({ state: "escalated", escalations: 3 })]);
    expect(later.notices.get(notice().ack_id)?.escalations).toBe(3);
    expect(later.dropped).toBe(0);
  });

  it("never takes an acknowledged notice back to escalated, and takes the acknowledgement", () => {
    const acked = notice({ state: "acknowledged", acknowledged_by: "watch_supervisor", acknowledged_at: "2026-10-02T12:02:00.000Z", escalations: 1 });
    expect(isLater(acked, notice({ state: "escalated", escalations: 5 }))).toBe(false);
    expect(isLater(notice({ state: "escalated", escalations: 5 }), acked)).toBe(true);
  });

  it("adds a notice it did not hold", () => {
    expect(mergeNotices(new Map(), [notice()]).notices.size).toBe(1);
  });
});

describe("order and groups", () => {
  const esc = notice({ ack_id: "A", state: "escalated", escalations: 1, received_at: "2026-10-02T12:05:00.000Z" });
  const escOlder = notice({ ack_id: "B", state: "escalated", escalations: 3, received_at: "2026-10-02T12:01:00.000Z" });
  const waiting = notice({ ack_id: "C", received_at: "2026-10-02T11:00:00.000Z" });
  const info = notice({ ack_id: "D", kind: "intent_notice", acknowledgement_required: false });
  const acked = notice({ ack_id: "E", state: "acknowledged", acknowledged_at: "2026-10-02T12:10:00.000Z" });

  it("lists escalated first, the longest waiting on top, then awaiting, informational, acknowledged", () => {
    expect(ordered([acked, info, waiting, esc, escOlder]).map((n) => n.ack_id)).toEqual(["B", "A", "C", "D", "E"]);
  });

  it("calls intent_notice and ended informational, and nonconformance awaiting", () => {
    expect(groupOf(info)).toBe("informational");
    expect(groupOf(notice({ kind: "ended", acknowledgement_required: false }))).toBe("informational");
    expect(groupOf(waiting)).toBe("awaiting");
  });

  it("counts what awaits a person", () => {
    expect(awaitingCount([acked, info, waiting, esc, escOlder])).toEqual({ escalated: 2, awaiting: 1 });
    expect(awaitingCount([acked, info])).toEqual({ escalated: 0, awaiting: 0 });
  });
});

describe("escalationNews", () => {
  it("is news for a first escalation and for each further one", () => {
    expect(escalationNews(notice(), notice({ state: "escalated", escalations: 1 }))).toBe(true);
    expect(escalationNews(undefined, notice({ state: "escalated", escalations: 1 }))).toBe(true);
    expect(escalationNews(notice({ state: "escalated", escalations: 1 }), notice({ state: "escalated", escalations: 2 }))).toBe(true);
  });

  it("is not news for the same escalation again, an acknowledgement, or a receipt", () => {
    expect(escalationNews(notice({ state: "escalated", escalations: 2 }), notice({ state: "escalated", escalations: 2 }))).toBe(false);
    expect(escalationNews(notice({ state: "escalated" }), notice({ state: "acknowledged" }))).toBe(false);
    expect(escalationNews(undefined, notice())).toBe(false);
    expect(escalationNews(notice({ state: "acknowledged" }), notice({ state: "escalated", escalations: 9 }))).toBe(false);
  });
});

const PAYLOAD = {
  schema: "coordination/annex_v/v1",
  notice_ref: "nc-1",
  kind: "nonconformance",
  ussp_id: "alpha",
  sent_at: "2026-10-02T12:00:00.000Z",
  intents: [
    {
      intent_ref: "2f8343be-6482-4d1b-a474-16847e01af1e",
      authorisation_number: "GEO-AUTH-1",
      state: "Nonconforming",
      time_start: "2026-10-02T11:50:00.000Z",
      time_end: "2026-10-02T12:30:00.000Z",
      volumes: [
        {
          volume: {
            outline_polygon: { vertices: [{ lat: 41.7, lng: 44.78 }, { lat: 41.7, lng: 44.8 }, { lat: 41.72, lng: 44.79 }] },
            altitude_lower: { value: 500, reference: "W84", units: "M" },
            altitude_upper: { value: 620, reference: "W84", units: "M" },
          },
        },
        { volume: { outline_circle: { center: { lat: 41.71, lng: 44.81 }, radius: { value: 300, units: "M" } } } },
        { volume: { outline_polygon: { vertices: [{ lat: 95, lng: 44 }] } } },
      ],
    },
    { intent_ref: 7 },
  ],
};

describe("payload", () => {
  it("copies the intents and counts the unreadable", () => {
    const { intents, malformed } = intentsOf(PAYLOAD);
    expect(intents).toEqual([
      {
        intentRef: "2f8343be-6482-4d1b-a474-16847e01af1e",
        authorisationNumber: "GEO-AUTH-1",
        state: "Nonconforming",
        timeStart: "2026-10-02T11:50:00.000Z",
        timeEnd: "2026-10-02T12:30:00.000Z",
      },
    ]);
    expect(malformed).toBe(1);
    expect(intentsOf(undefined)).toEqual({ intents: [], malformed: 0 });
  });

  it("draws a polygon as sent (ring closed) and a circle as its centre, and counts an unreadable volume", () => {
    const v = volumesOf("A", PAYLOAD, true);
    expect(v.features).toHaveLength(2);
    expect(v.features[0]?.geometry).toEqual({ type: "Polygon", coordinates: [[[44.78, 41.7], [44.8, 41.7], [44.79, 41.72], [44.78, 41.7]]] });
    expect(v.features[0]?.properties).toMatchObject({ lower_w84_m: 500, upper_w84_m: 620, emphasised: true });
    expect(v.features[1]?.geometry).toEqual({ type: "Point", coordinates: [44.81, 41.71] });
    expect(v.circles).toBe(1);
    expect(v.malformed).toBe(1);
  });
});

describe("note", () => {
  it("bounds the note in UTF-8 bytes, as the API does", () => {
    expect(noteBytes("abc")).toBe(3);
    expect(noteBytes("ა")).toBe(3);
  });

  it("sends the note when there is one and nothing otherwise", () => {
    expect(acknowledgeBody("  seen  ")).toEqual({ note: "seen" });
    expect(acknowledgeBody("   ")).toEqual({});
  });
});

function many(n: number, over: (i: number) => Partial<ApiNotice>): ApiNotice[] {
  return Array.from({ length: n }, (_, i) => notice({ ack_id: `01K6P0N${String(i).padStart(19, "0")}`, notice_ref: `n-${i}`, ...over(i) }));
}

function held(list: readonly ApiNotice[]): Map<string, ApiNotice> {
  return new Map(list.map((n) => [n.ack_id, n]));
}

describe("boundNotices", () => {
  it("keeps a held inbox at or under its bound as it is", () => {
    const m = held(many(3, () => ({})));
    const b = boundNotices(m, 3);
    expect(b.notices.size).toBe(3);
    expect(b.evicted).toBe(0);
  });

  it("past the bound, evicts the oldest acknowledged first, then the oldest informational, and counts them", () => {
    const acked = many(3, (i) => ({ state: "acknowledged", acknowledged_at: `2026-10-02T12:0${i}:00.000Z`, notice_ref: `a-${i}` })).map((n, i) => ({
      ...n,
      ack_id: `01K6P0A${String(i).padStart(19, "0")}`,
    }));
    const info = many(2, (i) => ({ kind: "intent_notice", acknowledgement_required: false, received_at: `2026-10-02T11:0${i}:00.000Z` })).map((n, i) => ({
      ...n,
      ack_id: `01K6P0I${String(i).padStart(19, "0")}`,
    }));
    const awaiting = many(2, () => ({})).map((n, i) => ({ ...n, ack_id: `01K6P0W${String(i).padStart(19, "0")}` }));
    const escalated = many(1, () => ({ state: "escalated", escalations: 2 })).map((n) => ({ ...n, ack_id: "01K6P0E0000000000000000000" }));
    const m = held([...acked, ...info, ...awaiting, ...escalated]);

    const four = boundNotices(m, 6);
    expect(four.evicted).toBe(2);
    expect([...four.notices.keys()]).not.toContain(acked[0]?.ack_id);
    expect([...four.notices.keys()]).not.toContain(acked[1]?.ack_id);
    expect([...four.notices.keys()]).toContain(acked[2]?.ack_id);

    const tight = boundNotices(m, 4);
    expect(tight.evicted).toBe(4);
    expect([...tight.notices.keys()].sort()).toEqual([...info.slice(1), ...awaiting, ...escalated].map((n) => n.ack_id).sort());
  });

  it("never evicts a notice that awaits a person, even past the bound", () => {
    const m = held([...many(5, () => ({})), notice({ ack_id: "01K6P0E0000000000000000000", state: "escalated", escalations: 1 })]);
    const b = boundNotices(m, 2);
    expect(b.notices.size).toBe(6);
    expect(b.evicted).toBe(0);
  });
});

describe("reconcileNotices", () => {
  it("takes the fresh list as the inbox, dropping what the API no longer lists", () => {
    const gone = notice({ ack_id: "01K6P0G0000000000000000000", state: "acknowledged", acknowledged_at: "2026-10-02T12:00:00.000Z" });
    const kept = notice();
    const r = reconcileNotices(held([gone, kept]), [kept], new Set());
    expect([...r.keys()]).toEqual([kept.ack_id]);
  });

  it("keeps a notice the stream brought while the list was read, and the later of two states", () => {
    const arrived = notice({ ack_id: "01K6P0S0000000000000000000" });
    const later = notice({ state: "escalated", escalations: 3 });
    const r = reconcileNotices(held([arrived, later]), [notice({ state: "escalated", escalations: 1 })], new Set([arrived.ack_id, later.ack_id]));
    expect(r.get(arrived.ack_id)).toBe(arrived);
    expect(r.get(later.ack_id)?.escalations).toBe(3);
    expect(r.size).toBe(2);
  });

  it("takes the fresh state of a listed notice when it is the later one", () => {
    const acked = notice({ state: "acknowledged", acknowledged_at: "2026-10-02T12:05:00.000Z" });
    const r = reconcileNotices(held([notice({ state: "escalated", escalations: 2 })]), [acked], new Set());
    expect(r.get(acked.ack_id)?.state).toBe("acknowledged");
  });
});
