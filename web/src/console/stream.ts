// A console WebSocket that hands the app every frame as sent, for a
// stream whose status and snapshot carry members the kit 0.1.0-rc.1's
// live client does not pass on: manned-feed's console/status/v1 has this
// system's adapters[] (api/openapi.yaml ConsoleStatus) and its snapshot's
// manned[] items carry state, relevant and source_instance, which the
// kit's MannedView has no place for (docs/PLAN.md section 15 row 51).
// Everything else is the kit's: the URL rule (same origin, no credential
// in it, M22), the frame and status parsers (a refused status frame is
// not applied, no threshold is ever filled in), the reconnect backoff
// with jitter forever (B-08) and the 4401 close that means "sign in
// again" (the session is re-checked by the server on every open stream).
//
// The session cookie rides the same-origin upgrade; the client sends
// nothing but console/subscribe/v1.
import {
  CLOSE_UNAUTHORIZED,
  DEFAULT_BACKOFF,
  STABLE_AFTER_MS,
  parseFrameText,
  parseStatusBody,
  reconnectDelayMs,
  resolveFeedUrl,
  type Backoff,
  type ConsoleFrame,
  type StatusSource,
  type SubscribeFrame,
} from "@rootxkit/uspace-ui/live";
import type { FeedStatusInput } from "@rootxkit/uspace-ui/status";
import type { ApiAdapterState } from "./manned";

const STATUS_SCHEMA = "console/status/v1";
const SNAPSHOT_SCHEMA = "console/snapshot/v1";

const ADAPTER_STATES: ReadonlySet<string> = new Set(["live", "stale", "disabled", "down", "unknown"]);

/** What the console shows of the stream (the kit's FeedStatusInput plus this system's extras). */
export interface StreamStatus extends FeedStatusInput {
  lastFrameAtMs: number | null;
  framesMalformed: number;
  unauthorized: boolean;
  /** Browser clock of the last valid status frame. */
  lastStatusAtMs: number | null;
  /** Server clock minus browser clock, from the last status frame. */
  clockOffsetMs: number | null;
  /** Failed attempts in the current run of failures. */
  attempt: number;
  nextRetryAtMs: number | null;
  /** The URL was refused by the kit's rule (named), so nothing is opened. */
  refused: string | null;
  /** The status frame's adapters[]; null before a status frame that carries it. */
  adapters: ApiAdapterState[] | null;
  /** Items of adapters[] that were not an adapter state (dropped, counted). */
  adaptersMalformed: number;
  sources: StatusSource[];
  cisVersion: string | null;
  cisAgeS: number | null;
  nats: string | null;
  /** manned-feed's relevance line (SC-22), when it sends one. */
  relevance: string | null;
}

export function initialStatus(nowMs: number): StreamStatus {
  return {
    connection: "connecting",
    sinceMs: nowMs,
    droppedFrames: 0,
    degraded: [],
    policyVersion: null,
    staleAfterS: null,
    liveMaxAgeS: null,
    serverTs: null,
    lastFrameAtMs: null,
    framesMalformed: 0,
    unauthorized: false,
    lastStatusAtMs: null,
    clockOffsetMs: null,
    attempt: 0,
    nextRetryAtMs: null,
    refused: null,
    adapters: null,
    adaptersMalformed: 0,
    sources: [],
    cisVersion: null,
    cisAgeS: null,
    nats: null,
    relevance: null,
  };
}

function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** adapters[] of a status body (AdapterState items); a malformed item is dropped and counted. */
export function adaptersOf(raw: unknown): { adapters: ApiAdapterState[] | null; malformed: number } {
  const b = obj(raw);
  if (b === null || !Array.isArray(b["adapters"])) return { adapters: null, malformed: 0 };
  const out: ApiAdapterState[] = [];
  let malformed = 0;
  for (const item of b["adapters"]) {
    const a = obj(item);
    const ok =
      a !== null &&
      typeof a["id"] === "string" &&
      a["id"] !== "" &&
      typeof a["state"] === "string" &&
      ADAPTER_STATES.has(a["state"]) &&
      typeof a["enabled"] === "boolean" &&
      (a["last_frame_at"] === undefined || a["last_frame_at"] === null || typeof a["last_frame_at"] === "string") &&
      (a["age_s"] === undefined || a["age_s"] === null || (typeof a["age_s"] === "number" && a["age_s"] >= 0));
    if (!ok) {
      malformed += 1;
      continue;
    }
    out.push(a as unknown as ApiAdapterState);
  }
  return { adapters: out, malformed };
}

/** The relevance line of a status body, or null. */
function relevanceOf(raw: unknown): string | null {
  const b = obj(raw);
  const r = b?.["relevance"];
  return typeof r === "string" && r !== "" ? r : null;
}

/** The manned[] items of a snapshot body, or null when the body has none. */
export function snapshotItems(raw: unknown, member: string): unknown[] | null {
  const b = obj(raw);
  if (b === null) return null;
  const items = b[member];
  return Array.isArray(items) ? items : null;
}

/** The part of the browser's WebSocket the client uses (a fake one in tests). */
export interface SocketLike {
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: { code: number }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  send(data: string): void;
  close(code?: number): void;
}

export interface StreamOptions {
  /** The stream's path, relative to the page (same origin). */
  url: string;
  /** Every frame that is neither status nor snapshot. */
  onFrame(frame: ConsoleFrame, receivedAtMs: number): void;
  /** Every snapshot frame (the app reads its own members). */
  onSnapshot(frame: ConsoleFrame, receivedAtMs: number): void;
  /** The session is gone (close 4401): once per outage. */
  onUnauthorized(): void;
  now?: () => number;
  random?: () => number;
  backoff?: Backoff;
  /** The page URL the path resolves against; the browser's by default. */
  page?: () => string | undefined;
  /** Opens a socket; the browser's WebSocket by default. */
  open?: (url: string) => SocketLike;
  /** Schedules a retry; setTimeout by default. */
  schedule?: (fn: () => void, ms: number) => unknown;
  cancel?: (handle: unknown) => void;
}

/** The client, without React (useConsoleStream wraps it). Never throws from a socket event. */
export class StreamClient {
  private status: StreamStatus;
  private readonly listeners = new Set<() => void>();
  private socket: SocketLike | null = null;
  private timer: unknown = null;
  private running = false;
  private run = 0;
  private liveAtMs: number | null = null;
  private notified = false;
  private pending: SubscribeFrame | null = null;

  constructor(private opts: StreamOptions) {
    this.status = initialStatus(this.now());
  }

  setOptions(opts: StreamOptions): void {
    this.opts = opts;
  }

  getStatus = (): StreamStatus => this.status;

  subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn);
    return () => {
      this.listeners.delete(fn);
    };
  };

  start(): void {
    if (this.running) return;
    this.running = true;
    this.run += 1;
    this.connect(this.run);
  }

  stop(): void {
    this.running = false;
    this.run += 1;
    if (this.timer !== null) (this.opts.cancel ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>)))(this.timer);
    this.timer = null;
    const s = this.socket;
    this.socket = null;
    if (s !== null) {
      s.onopen = null;
      s.onmessage = null;
      s.onclose = null;
      s.onerror = null;
      try {
        s.close(1000);
      } catch {
        // Closing a socket that never opened may throw; it is gone either way.
      }
    }
  }

  /** Sends a console/subscribe/v1 now when open, and again on every reconnect. */
  send = (frame: SubscribeFrame): void => {
    this.pending = frame;
    this.flush();
  };

  private now(): number {
    return (this.opts.now ?? Date.now)();
  }

  private set(patch: Partial<StreamStatus>): void {
    this.status = { ...this.status, ...patch };
    for (const l of this.listeners) l();
  }

  private flush(): void {
    if (this.socket === null || this.pending === null) return;
    try {
      this.socket.send(JSON.stringify(this.pending));
    } catch {
      // Not open yet: onopen sends it.
    }
  }

  private connect(run: number): void {
    if (run !== this.run || !this.running) return;
    const page = this.opts.page ? this.opts.page() : typeof window === "undefined" ? undefined : window.location.href;
    const resolved = resolveFeedUrl(this.opts.url, page);
    if ("refused" in resolved) {
      this.set({ connection: "down", sinceMs: this.now(), refused: resolved.refused });
      return;
    }
    let socket: SocketLike;
    try {
      socket = this.opts.open ? this.opts.open(resolved.url) : (new WebSocket(resolved.url) as unknown as SocketLike);
    } catch {
      this.retry(run, null);
      return;
    }
    this.socket = socket;
    socket.onopen = () => {
      if (run !== this.run) return;
      this.flush();
    };
    socket.onmessage = (ev) => {
      if (run !== this.run) return;
      this.onMessage(ev.data);
    };
    socket.onerror = () => {
      // A close follows; the retry is scheduled there.
    };
    socket.onclose = (ev) => {
      if (run !== this.run) return;
      this.socket = null;
      const upMs = this.liveAtMs === null ? null : this.now() - this.liveAtMs;
      this.liveAtMs = null;
      if (ev.code === CLOSE_UNAUTHORIZED) {
        this.set({ unauthorized: true });
        if (!this.notified) {
          this.notified = true;
          try {
            this.opts.onUnauthorized();
          } catch {
            // The app's callback is the app's; the stream keeps retrying.
          }
        }
      }
      this.retry(run, upMs);
    };
  }

  private retry(run: number, upMs: number | null): void {
    if (run !== this.run || !this.running) return;
    const stable = upMs !== null && upMs >= STABLE_AFTER_MS;
    const attempt = stable ? 0 : this.status.attempt;
    const delay = reconnectDelayMs(attempt, this.opts.backoff ?? DEFAULT_BACKOFF, (this.opts.random ?? Math.random)());
    const nowMs = this.now();
    this.set({
      connection: "down",
      sinceMs: this.status.connection === "down" ? this.status.sinceMs : nowMs,
      attempt: attempt + 1,
      nextRetryAtMs: nowMs + delay,
    });
    const schedule = this.opts.schedule ?? ((fn: () => void, ms: number) => setTimeout(fn, ms));
    this.timer = schedule(() => this.connect(run), delay);
  }

  private onMessage(data: unknown): void {
    const nowMs = this.now();
    const frame = parseFrameText(data);
    if (frame === null) {
      this.set({ lastFrameAtMs: nowMs, framesMalformed: this.status.framesMalformed + 1 });
      return;
    }
    if (frame.schema === STATUS_SCHEMA) {
      this.onStatus(frame, nowMs);
      return;
    }
    this.set({ lastFrameAtMs: nowMs });
    try {
      if (frame.schema === SNAPSHOT_SCHEMA) this.opts.onSnapshot(frame, nowMs);
      else this.opts.onFrame(frame, nowMs);
    } catch {
      // One frame the app could not take must not end the stream.
    }
  }

  private onStatus(frame: ConsoleFrame, nowMs: number): void {
    const body = parseStatusBody(frame.body);
    if (body === null) {
      this.set({ lastFrameAtMs: nowMs, framesMalformed: this.status.framesMalformed + 1 });
      return;
    }
    const serverMs = Date.parse(body.serverTs);
    const { adapters, malformed } = adaptersOf(frame.body);
    if (this.status.connection !== "live") {
      this.liveAtMs = nowMs;
      this.notified = false;
    }
    this.set({
      connection: "live",
      sinceMs: this.status.connection === "live" ? this.status.sinceMs : nowMs,
      droppedFrames: body.droppedFrames,
      degraded: body.degraded,
      policyVersion: body.policyVersion,
      staleAfterS: body.staleAfterS,
      liveMaxAgeS: body.liveMaxAgeS,
      serverTs: body.serverTs,
      lastFrameAtMs: nowMs,
      lastStatusAtMs: nowMs,
      clockOffsetMs: Number.isFinite(serverMs) ? serverMs - nowMs : null,
      unauthorized: false,
      attempt: 0,
      nextRetryAtMs: null,
      refused: null,
      adapters,
      adaptersMalformed: this.status.adaptersMalformed + malformed,
      sources: body.sources,
      cisVersion: body.cisVersion,
      cisAgeS: body.cisAgeS,
      nats: body.nats,
      relevance: relevanceOf(frame.body),
    });
  }
}

/**
 * Whether the stream has said nothing for longer than its own
 * stale_after_s while it is open: a stream that stops talking is shown
 * as silent, never as live. False before a status frame (no threshold).
 */
export function streamSilent(s: Pick<StreamStatus, "connection" | "lastStatusAtMs" | "staleAfterS">, nowMs: number): boolean {
  if (s.connection !== "live" || s.lastStatusAtMs === null || s.staleAfterS === null) return false;
  return nowMs - s.lastStatusAtMs > s.staleAfterS * 1000;
}
