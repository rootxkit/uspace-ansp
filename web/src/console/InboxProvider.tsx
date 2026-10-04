"use client";

// The coordination inbox every signed-in page shares: GET
// /v1/coordination/inbox, then the coordination stream (WS
// /v1/coordination/stream on api, same origin, the session cookie on the
// upgrade, M22) merged on top. The list is read again whenever the
// stream comes back live, because the kit's live client does not hand
// the snapshot's notices to the app (docs/PLAN.md section 15 row 49 (5)).
// A 4401 close is the console's "signed out, sign in again". A person
// may opt in, in this browser only, to a browser notification for each
// escalation (the permission is the browser's, the choice is kept in
// localStorage as a per-viewer convenience).
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { useFeed, type LiveFeed } from "@rootxkit/uspace-ui/live";
import { failureOf, type CallFailure } from "../api/client";
import { useConsole } from "./context";
import { escalationNews, mergeNotices, noticeOf, type ApiNotice } from "./inbox";
import { useInBrowser } from "./ui";

/** The console's coordination stream (api/openapi.yaml streamCoordination). */
export const COORDINATION_STREAM_PATH = "/v1/coordination/stream";
/** The inbox read's bound (api/openapi.yaml Limit maximum); the API says when it cut the list. */
export const INBOX_LIMIT = 1000;
/** Where this browser keeps the opt-in. */
export const NOTIFY_KEY = "uspace-ansp:inbox-notify";

export type NotifyState = "unsupported" | "off" | "on" | "denied";

export interface InboxValue {
  notices: ReadonlyMap<string, ApiNotice>;
  loaded: boolean;
  truncated: boolean;
  failure: CallFailure | null;
  feed: LiveFeed;
  /** Frames that named an earlier state than the one held (dropped). */
  dropped: number;
  /** Frames on the stream that were not an inbox item (ignored, counted). */
  ignored: number;
  reload(): void;
  /** A notice as an acknowledgement answered it. */
  put(n: ApiNotice): void;
  notify: NotifyState;
  setNotify(on: boolean): void;
}

const Ctx = createContext<InboxValue | null>(null);

export function useInbox(): InboxValue {
  const v = useContext(Ctx);
  if (v === null) throw new Error("useInbox outside InboxProvider");
  return v;
}

function readOptIn(): boolean {
  try {
    return window.localStorage.getItem(NOTIFY_KEY) === "on";
  } catch {
    return false;
  }
}

function writeOptIn(on: boolean): void {
  try {
    if (on) window.localStorage.setItem(NOTIFY_KEY, "on");
    else window.localStorage.removeItem(NOTIFY_KEY);
  } catch {
    // A browser that keeps nothing: the choice lasts this page only.
  }
}

function notifyStateOf(optIn: boolean): NotifyState {
  if (typeof window === "undefined" || !("Notification" in window)) return "unsupported";
  if (Notification.permission === "denied") return "denied";
  return optIn && Notification.permission === "granted" ? "on" : "off";
}

export function InboxProvider({ children }: { children: ReactNode }) {
  const t = useT();
  const { client, markSignedOut } = useConsole();
  const [notices, setNotices] = useState<ReadonlyMap<string, ApiNotice>>(new Map());
  const held = useRef<ReadonlyMap<string, ApiNotice>>(new Map());
  const [loaded, setLoaded] = useState(false);
  const [truncated, setTruncated] = useState(false);
  const [failure, setFailure] = useState<CallFailure | null>(null);
  const [dropped, setDropped] = useState(0);
  const [ignored, setIgnored] = useState(0);
  const [tick, setTick] = useState(0);
  const [optIn, setOptIn] = useState(() => typeof window !== "undefined" && readOptIn());
  // Bumped when the browser answers a permission request, so the state is read again.
  const [, setAsked] = useState(0);
  const browser = useInBrowser();
  const notify: NotifyState = browser ? notifyStateOf(optIn) : "off";
  const seq = useRef(0);

  const apply = useCallback((incoming: readonly ApiNotice[]) => {
    const merged = mergeNotices(held.current, incoming);
    held.current = merged.notices;
    setNotices(merged.notices);
    if (merged.dropped > 0) setDropped((n) => n + merged.dropped);
  }, []);

  useEffect(() => {
    const mine = ++seq.current;
    client
      .GET("/v1/coordination/inbox", { params: { query: { limit: INBOX_LIMIT } } })
      .then(({ data }) => {
        if (mine !== seq.current || data === undefined) return;
        apply(data.notices);
        setTruncated(data.truncated === true);
        setFailure(null);
        setLoaded(true);
      })
      .catch((err: unknown) => {
        if (mine === seq.current) setFailure(failureOf(err));
      });
  }, [client, tick, apply]);

  // The kit gives the feed the newest options on every render, so this
  // callback reads the current opt-in and language.
  const feed = useFeed({
    url: COORDINATION_STREAM_PATH,
    onFrame: (frame) => {
      const n = noticeOf(frame);
      if (n === null) {
        setIgnored((x) => x + 1);
        return;
      }
      const news = escalationNews(held.current.get(n.ack_id), n);
      apply([n]);
      if (news && optIn && typeof window !== "undefined" && "Notification" in window && Notification.permission === "granted") {
        try {
          new Notification(t("ansp.inbox.notification.title"), {
            body: t("ansp.inbox.notification.body", { kind: t(`ansp.inbox.kind.${n.kind}`), ussp: n.ussp_id, escalations: n.escalations ?? 1 }),
            tag: `ansp-notice-${n.ack_id}`,
          });
        } catch {
          // A browser that refuses to show it: the page still says it, loudest.
        }
      }
    },
    onUnauthorized: markSignedOut,
  });

  // Back live after being down: read the inbox again (the frames between
  // were not seen here, and the snapshot's notices are not handed on).
  const connection = feed.connection;
  const lost = useRef(false);
  const seenLive = useRef(false);
  useEffect(() => {
    if (connection === "live") {
      if (lost.current) setTick((n) => n + 1);
      seenLive.current = true;
      lost.current = false;
    } else if (connection === "down" && seenLive.current) {
      lost.current = true;
    }
  }, [connection]);

  const reload = useCallback(() => setTick((n) => n + 1), []);
  const put = useCallback((n: ApiNotice) => apply([n]), [apply]);
  const setNotify = useCallback((on: boolean) => {
    if (!on) {
      writeOptIn(false);
      setOptIn(false);
      return;
    }
    if (typeof window === "undefined" || !("Notification" in window)) return;
    void Notification.requestPermission().then((p) => {
      const granted = p === "granted";
      writeOptIn(granted);
      setOptIn(granted);
      setAsked((n) => n + 1);
    });
  }, []);

  const value = useMemo(
    () => ({ notices, loaded, truncated, failure, feed, dropped, ignored, reload, put, notify, setNotify }),
    [notices, loaded, truncated, failure, feed, dropped, ignored, reload, put, notify, setNotify],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
