// The console stream client against a fake socket: live only on a valid
// status frame (a refused one changes nothing), adapters[] read with its
// malformed items counted, snapshots and frames handed on, 4401 told
// once per outage, reconnect forever with backoff, the subscribe frame
// sent on open and again after a reconnect, and silence past the
// stream's own stale_after_s shown (E-01 pairs).
import { describe, expect, it } from "vitest";
import { subscribeFrame } from "@rootxkit/uspace-ui/live";
import { adaptersOf, StreamClient, streamSilent, type SocketLike, type StreamOptions } from "./stream";

class FakeSocket implements SocketLike {
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: { code: number }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  sent: string[] = [];
  closed: number | null = null;
  constructor(readonly url: string) {}
  send(data: string) {
    this.sent.push(data);
  }
  close(code?: number) {
    this.closed = code ?? 1000;
  }
}

const NOW = Date.parse("2026-10-02T12:00:00.000Z");

function envelope(schema: string, body: unknown): string {
  return JSON.stringify({
    schema,
    msg_id: "01K6PW0000000000000000000A",
    producer: "ansp/manned-feed",
    ts: null,
    rx_ts: "2026-10-02T12:00:00.000Z",
    captured_at: "2026-10-02T12:00:00.000Z",
    time_source: "system",
    backlog: false,
    body,
  });
}

function status(over: Record<string, unknown> = {}): string {
  return envelope("console/status/v1", {
    connection_id: "c1",
    server_ts: "2026-10-02T12:00:01.000Z",
    policy_version: "7",
    stale_after_s: 15,
    live_max_age_s: 3,
    dropped_frames: 2,
    degraded: ["cis_projection_stale"],
    sources: [
      {
        source: "ansp_feed",
        source_instance: "sbs-1",
        state: "disabled",
        since: "2026-10-02T11:00:00.000Z",
        age_s: 3600,
        disabled_by: "instance",
        disabled_by_who: "admin",
        counters: { accepted: 1, refused: 4 },
      },
    ],
    adapters: [
      { id: "replay-1", state: "live", enabled: true, last_frame_at: "2026-10-02T12:00:00.000Z", age_s: 1 },
      { id: "sbs-1", state: "disabled", enabled: false, last_frame_at: null, age_s: null },
      { id: "", state: "live", enabled: true },
    ],
    cis_version: "42",
    cis_age_s: 12,
    nats: "connected",
    relevance: "evaluated against cis 42",
    ...over,
  });
}

function harness(over: Partial<StreamOptions> = {}) {
  const sockets: FakeSocket[] = [];
  const timers: { fn: () => void; ms: number }[] = [];
  const frames: string[] = [];
  const snapshots: string[] = [];
  let unauthorized = 0;
  let now = NOW;
  const client = new StreamClient({
    url: "/v1/manned-traffic/stream",
    page: () => "https://ansp.example.test/en/picture",
    open: (url) => {
      const s = new FakeSocket(url);
      sockets.push(s);
      return s;
    },
    schedule: (fn, ms) => {
      timers.push({ fn, ms });
      return timers.length;
    },
    cancel: () => undefined,
    now: () => now,
    random: () => 0.5,
    onFrame: (f) => frames.push(f.schema),
    onSnapshot: (f) => snapshots.push(f.schema),
    onUnauthorized: () => (unauthorized += 1),
    ...over,
  });
  return {
    client,
    sockets,
    timers,
    frames,
    snapshots,
    unauthorized: () => unauthorized,
    advance: (ms: number) => (now += ms),
    last: () => sockets[sockets.length - 1] as FakeSocket,
  };
}

describe("StreamClient", () => {
  it("opens the same-origin wss URL and is connecting until a status frame", () => {
    const h = harness();
    h.client.start();
    expect(h.last().url).toBe("wss://ansp.example.test/v1/manned-traffic/stream");
    expect(h.client.getStatus().connection).toBe("connecting");
  });

  it("is live on a valid status frame, with the frame's thresholds and extras", () => {
    const h = harness();
    h.client.start();
    h.last().onmessage?.({ data: status() });
    const s = h.client.getStatus();
    expect(s.connection).toBe("live");
    expect(s.staleAfterS).toBe(15);
    expect(s.policyVersion).toBe("7");
    expect(s.droppedFrames).toBe(2);
    expect(s.degraded).toEqual(["cis_projection_stale"]);
    expect(s.cisAgeS).toBe(12);
    expect(s.relevance).toBe("evaluated against cis 42");
    expect(s.adapters?.map((a) => a.id)).toEqual(["replay-1", "sbs-1"]);
    expect(s.adaptersMalformed).toBe(1);
    expect(s.sources[0]?.disabledByWho).toBe("admin");
    expect(s.clockOffsetMs).toBe(1000);
  });

  it("applies nothing of a status frame that breaks the schema, and counts it", () => {
    const h = harness();
    h.client.start();
    h.last().onmessage?.({ data: status({ stale_after_s: 0 }) });
    const s = h.client.getStatus();
    expect(s.connection).toBe("connecting");
    expect(s.staleAfterS).toBeNull();
    expect(s.framesMalformed).toBe(1);
  });

  it("hands snapshots and other frames to the app, and counts a malformed frame", () => {
    const h = harness();
    h.client.start();
    h.last().onmessage?.({ data: envelope("console/snapshot/v1", { tracks: [], alerts: [], manned: [], zones_version: null }) });
    h.last().onmessage?.({ data: envelope("track/manned/v1", {}) });
    h.last().onmessage?.({ data: "{not json" });
    expect(h.snapshots).toEqual(["console/snapshot/v1"]);
    expect(h.frames).toEqual(["track/manned/v1"]);
    expect(h.client.getStatus().framesMalformed).toBe(1);
  });

  it("sends the subscribe frame on open and again after a reconnect", () => {
    const h = harness();
    h.client.send(subscribeFrame([44.6, 41.6, 45, 41.9], ["manned"]));
    h.client.start();
    h.last().onopen?.({});
    expect(JSON.parse(h.last().sent[0] ?? "{}")).toEqual({ schema: "console/subscribe/v1", body: { bbox: [44.6, 41.6, 45, 41.9], layers: ["manned"] } });
    h.last().onclose?.({ code: 1006 });
    h.timers[0]?.fn();
    h.last().onopen?.({});
    expect(h.sockets).toHaveLength(2);
    expect(h.last().sent).toHaveLength(1);
  });

  it("tells the app once of a 4401 close and keeps retrying; a live stream re-arms it", () => {
    const h = harness();
    h.client.start();
    h.last().onclose?.({ code: 4401 });
    h.timers[0]?.fn();
    h.last().onclose?.({ code: 4401 });
    expect(h.unauthorized()).toBe(1);
    expect(h.client.getStatus().unauthorized).toBe(true);
    h.timers[1]?.fn();
    h.last().onmessage?.({ data: status() });
    expect(h.client.getStatus().unauthorized).toBe(false);
    h.last().onclose?.({ code: 4401 });
    expect(h.unauthorized()).toBe(2);
  });

  it("does not call another close unauthorized", () => {
    const h = harness();
    h.client.start();
    h.last().onclose?.({ code: 1013 });
    expect(h.unauthorized()).toBe(0);
    expect(h.client.getStatus().connection).toBe("down");
  });

  it("backs off while failures repeat and starts again after a stable connection", () => {
    const h = harness();
    h.client.start();
    h.last().onclose?.({ code: 1006 });
    h.timers[0]?.fn();
    h.last().onclose?.({ code: 1006 });
    expect((h.timers[1]?.ms ?? 0) > (h.timers[0]?.ms ?? 0)).toBe(true);
    h.timers[1]?.fn();
    h.last().onmessage?.({ data: status() });
    h.advance(60_000);
    h.last().onclose?.({ code: 1006 });
    expect(h.timers[2]?.ms).toBe(h.timers[0]?.ms);
  });

  it("keeps the time it went down across failed retries", () => {
    const h = harness();
    h.client.start();
    h.last().onclose?.({ code: 1006 });
    const since = h.client.getStatus().sinceMs;
    h.advance(5000);
    h.timers[0]?.fn();
    h.last().onclose?.({ code: 1006 });
    expect(h.client.getStatus().sinceMs).toBe(since);
  });

  it("opens nothing for a URL on another origin, and says why", () => {
    const h = harness({ url: "wss://elsewhere.example.test/v1/manned-traffic/stream" });
    h.client.start();
    expect(h.sockets).toHaveLength(0);
    expect(h.client.getStatus().refused).not.toBeNull();
    expect(h.client.getStatus().connection).toBe("down");
  });

  it("stops: closes the socket and ignores what it says afterwards", () => {
    const h = harness();
    h.client.start();
    const s = h.last();
    h.client.stop();
    expect(s.closed).toBe(1000);
    s.onmessage?.({ data: status() });
    expect(h.client.getStatus().connection).toBe("connecting");
  });
});

describe("adaptersOf", () => {
  it("is null without adapters[], and an empty list for an empty one", () => {
    expect(adaptersOf({}).adapters).toBeNull();
    expect(adaptersOf({ adapters: [] }).adapters).toEqual([]);
  });
});

describe("streamSilent", () => {
  it("is silent past stale_after_s without a status frame, and not before", () => {
    const s = { connection: "live" as const, lastStatusAtMs: NOW, staleAfterS: 15 };
    expect(streamSilent(s, NOW + 15_000)).toBe(false);
    expect(streamSilent(s, NOW + 15_001)).toBe(true);
  });

  it("says nothing without a threshold or while not live", () => {
    expect(streamSilent({ connection: "live", lastStatusAtMs: NOW, staleAfterS: null }, NOW + 1e9)).toBe(false);
    expect(streamSilent({ connection: "down", lastStatusAtMs: NOW, staleAfterS: 15 }, NOW + 1e9)).toBe(false);
  });
});
