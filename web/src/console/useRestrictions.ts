"use client";

// The restriction list and the open delivery alarms, live: GET
// /v1/restrictions and GET /v1/delivery-alarms, then every
// restriction/state/v1 frame of the shared stream merged on top
// (restrictions.ts). The list is read again when the stream comes back
// live (the snapshot it missed is not replayed to the app) and when a
// frame names a restriction the list does not hold.
import { useEffect, useRef, useState } from "react";
import type { CallFailure } from "../api/client";
import { failureOf } from "../api/client";
import { useConsole } from "./context";
import type { ApiAlarm, ApiRestriction } from "./delivery";
import { mergeAlarm, mergeState, stateBodyOf } from "./restrictions";

/** The list's bound (api/openapi.yaml Limit). Display-only: the API says when it cut the list. */
export const LIST_LIMIT = 500;

export interface LiveRestrictions {
  restrictions: ApiRestriction[] | null;
  truncated: boolean;
  cisVersion: string | null;
  cisAgeS: number | null;
  alarms: ApiAlarm[];
  failure: CallFailure | null;
  alarmsFailure: CallFailure | null;
  /** Frames applied since the page opened (the stream is doing its job). */
  framesApplied: number;
  reload(): void;
}

export function useRestrictions(state: string | null): LiveRestrictions {
  const { client, feed, onFrame } = useConsole();
  const [restrictions, setRestrictions] = useState<ApiRestriction[] | null>(null);
  const [meta, setMeta] = useState({ truncated: false, cisVersion: null as string | null, cisAgeS: null as number | null });
  const [alarms, setAlarms] = useState<ApiAlarm[]>([]);
  const [failure, setFailure] = useState<CallFailure | null>(null);
  const [alarmsFailure, setAlarmsFailure] = useState<CallFailure | null>(null);
  const [framesApplied, setFramesApplied] = useState(0);
  const [tick, setTick] = useState(0);
  const seq = useRef(0);
  const list = useRef<ApiRestriction[] | null>(null);

  useEffect(() => {
    const mine = ++seq.current;
    const query = state === null ? { limit: LIST_LIMIT } : { limit: LIST_LIMIT, state: state as ApiRestriction["state"] };
    client
      .GET("/v1/restrictions", { params: { query } })
      .then(({ data }) => {
        if (mine !== seq.current || data === undefined) return;
        list.current = data.restrictions;
        setRestrictions(data.restrictions);
        setMeta({ truncated: data.truncated === true, cisVersion: data.cis_version, cisAgeS: data.cis_age_s });
        setFailure(null);
      })
      .catch((err: unknown) => {
        if (mine === seq.current) setFailure(failureOf(err));
      });
    client
      .GET("/v1/delivery-alarms", { params: { query: { limit: LIST_LIMIT } } })
      .then(({ data }) => {
        if (mine !== seq.current || data === undefined) return;
        setAlarms(data.alarms);
        setAlarmsFailure(null);
      })
      .catch((err: unknown) => {
        if (mine === seq.current) setAlarmsFailure(failureOf(err));
      });
  }, [client, state, tick]);

  // Back live after being down: read the list again (the frames between
  // were not seen here).
  const connection = feed.connection;
  const seenLive = useRef(false);
  const lost = useRef(false);
  useEffect(() => {
    if (connection === "live") {
      if (lost.current) setTick((n) => n + 1);
      seenLive.current = true;
      lost.current = false;
    } else if (connection === "down" && seenLive.current) {
      lost.current = true;
    }
  }, [connection]);

  useEffect(
    () =>
      onFrame((frame) => {
        const body = stateBodyOf(frame);
        if (body === null || list.current === null) return;
        const merged = mergeState(list.current, body);
        if (merged.unknown) {
          setTick((n) => n + 1);
          return;
        }
        if (merged.stale) return;
        list.current = merged.restrictions;
        setRestrictions(merged.restrictions);
        setAlarms((prev) => mergeAlarm(prev, body.alarm));
        setFramesApplied((n) => n + 1);
      }),
    [onFrame],
  );

  return {
    restrictions,
    ...meta,
    alarms,
    failure,
    alarmsFailure,
    framesApplied,
    reload: () => setTick((n) => n + 1),
  };
}
