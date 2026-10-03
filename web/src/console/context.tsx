"use client";

// The signed-in console: who the caller is (GET /v1/auth/me), the client
// every page calls through, and the one restriction stream every page
// shares (WS /v1/restrictions/stream, same origin, the session cookie on
// the upgrade, M22). A 401 from any call, or a 4401 close of the stream,
// is "signed out, sign in again"; the role shown here only arranges the
// page, the API decides every request.
import { createContext, useCallback, useContext, useEffect, useEffectEvent, useMemo, useRef, useState, type ReactNode } from "react";
import { useLang } from "@rootxkit/uspace-ui/i18n";
import { useFeed, type ConsoleFrame, type LiveFeed } from "@rootxkit/uspace-ui/live";
import type { components } from "../api/types";
import { consoleClient, failureOf, type CallFailure, type ConsoleClient } from "../api/client";
import { isRole, type ConsoleRole } from "./roles";

export type ApiMe = components["schemas"]["Me"];

/** The console's restriction stream (api/openapi.yaml streamRestrictions). */
export const RESTRICTION_STREAM_PATH = "/v1/restrictions/stream";

type FrameListener = (frame: ConsoleFrame) => void;

export interface ConsoleContextValue {
  client: ConsoleClient;
  me: ApiMe | null;
  role: ConsoleRole | null;
  /** /me could not be read for a reason other than a 401. */
  meFailure: CallFailure | null;
  /** A call answered 401 or the stream closed 4401: the session is gone. */
  signedOut: boolean;
  feed: LiveFeed;
  /** Every frame the kit does not store itself (restriction/state/v1). */
  onFrame(listener: FrameListener): () => void;
}

const Ctx = createContext<ConsoleContextValue | null>(null);

export function useConsole(): ConsoleContextValue {
  const v = useContext(Ctx);
  if (v === null) throw new Error("useConsole outside ConsoleProvider");
  return v;
}

export function loginPath(lang: string): string {
  return `/${lang}/login`;
}

export function ConsoleProvider({ children }: { children: ReactNode }) {
  const { lang } = useLang();
  const [signedOut, setSignedOut] = useState(false);
  const toSignedOut = useCallback(() => setSignedOut(true), []);
  const client = useMemo(() => consoleClient(() => lang, toSignedOut), [lang, toSignedOut]);
  const [me, setMe] = useState<ApiMe | null>(null);
  const [meFailure, setMeFailure] = useState<CallFailure | null>(null);
  const listeners = useRef(new Set<FrameListener>());

  useEffect(() => {
    let live = true;
    client
      .GET("/v1/auth/me")
      .then(({ data }) => {
        if (!live || data === undefined) return;
        setMe(data);
        setMeFailure(null);
      })
      .catch((err: unknown) => {
        if (!live) return;
        const f = failureOf(err);
        // A 401 is the client's onUnauthorized: signed out.
        if (f.status !== 401) setMeFailure(f);
      });
    return () => {
      live = false;
    };
  }, [client]);

  const feed = useFeed({
    url: RESTRICTION_STREAM_PATH,
    onFrame: (frame) => {
      for (const l of listeners.current) l(frame);
    },
    onUnauthorized: toSignedOut,
  });

  const onFrame = useCallback((listener: FrameListener) => {
    listeners.current.add(listener);
    return () => {
      listeners.current.delete(listener);
    };
  }, []);

  const role = me !== null && isRole(me.role) ? me.role : null;
  const value = useMemo(
    () => ({ client, me, role, meFailure, signedOut: signedOut || feed.unauthorized, feed, onFrame }),
    [client, me, role, meFailure, signedOut, feed, onFrame],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export interface Loaded<T> {
  data: T | null;
  failure: CallFailure | null;
  loading: boolean;
  reload(): void;
}

/**
 * One read of the API: `load` runs on mount, when `key` changes and on
 * `reload()`. An answer that arrives after a newer request is dropped. A
 * failure keeps the last data and is shown beside it.
 */
export function useLoad<T>(load: (c: ConsoleClient) => Promise<T>, key: string): Loaded<T> {
  const { client } = useConsole();
  const [tick, setTick] = useState(0);
  const [settled, setSettled] = useState<{ request: string; data: T | null; failure: CallFailure | null }>({
    request: "",
    data: null,
    failure: null,
  });
  const seq = useRef(0);
  const request = `${key}#${tick}`;
  const run = useEffectEvent((c: ConsoleClient) => load(c));

  useEffect(() => {
    const mine = ++seq.current;
    run(client)
      .then((d) => {
        if (mine === seq.current) setSettled({ request, data: d, failure: null });
      })
      .catch((err: unknown) => {
        if (mine === seq.current) setSettled((prev) => ({ request, data: prev.data, failure: failureOf(err) }));
      });
  }, [client, request]);

  const reload = useCallback(() => setTick((n) => n + 1), []);
  return { data: settled.data, failure: settled.failure, loading: settled.request !== request, reload };
}
