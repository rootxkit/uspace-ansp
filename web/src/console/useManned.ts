"use client";

// The manned picture's stream (WS /v1/manned-traffic/stream on
// manned-feed, same origin, the session cookie on the upgrade, M22):
// track/manned/v1 frames and the snapshot's manned[] go to the picture
// (manned.ts), status frames to the status; a 4401 close is the
// console's "signed out, sign in again". The picture re-renders at most
// every RENDER_MS however many frames arrive (a display period).
import { useEffect, useState, useSyncExternalStore } from "react";
import type { SubscribeFrame } from "@rootxkit/uspace-ui/live";
import { MannedPicture, type Aircraft } from "./manned";
import { snapshotItems, StreamClient, type StreamOptions, type StreamStatus } from "./stream";

/** The manned stream (api/openapi.yaml streamMannedTraffic). */
export const MANNED_STREAM_PATH = "/v1/manned-traffic/stream";

/** How often the picture is redrawn at most while frames arrive. Display-only. */
export const RENDER_MS = 250;

export interface MannedStream {
  status: StreamStatus;
  aircraft: ReadonlyMap<string, Aircraft>;
  picture: MannedPicture;
  send(frame: SubscribeFrame): void;
}

/** A store whose listeners hear of changes at most every `ms`. */
function throttled(subscribe: (fn: () => void) => () => void, ms: number): (fn: () => void) => () => void {
  return (fn) => {
    let timer: ReturnType<typeof setTimeout> | null = null;
    const off = subscribe(() => {
      if (timer !== null) return;
      timer = setTimeout(() => {
        timer = null;
        fn();
      }, ms);
    });
    return () => {
      off();
      if (timer !== null) clearTimeout(timer);
    };
  };
}

/** The client's options: frames and snapshots to the picture, 4401 to the console. */
function optionsFor(picture: MannedPicture, onUnauthorized: () => void): StreamOptions {
  return {
    url: MANNED_STREAM_PATH,
    onFrame: (frame, at) => {
      picture.apply(frame, at);
    },
    onSnapshot: (frame, at) => {
      const items = snapshotItems(frame.body, "manned");
      if (items !== null) picture.replace(items, at);
    },
    onUnauthorized,
  };
}

export function useMannedStream(onUnauthorized: () => void): MannedStream {
  const [picture] = useState(() => new MannedPicture());
  const [client] = useState(() => new StreamClient(optionsFor(picture, onUnauthorized)));
  useEffect(() => {
    client.setOptions(optionsFor(picture, onUnauthorized));
  }, [client, picture, onUnauthorized]);
  useEffect(() => {
    client.start();
    return () => client.stop();
  }, [client]);
  const status = useSyncExternalStore(client.subscribe, client.getStatus, client.getStatus);
  const [subscribePicture] = useState(() => throttled(picture.subscribe, RENDER_MS));
  const aircraft = useSyncExternalStore(subscribePicture, picture.snapshot, picture.snapshot);
  return { status, aircraft, picture, send: client.send };
}
