"use client";

// /<locale>/picture: the manned traffic picture (2021/665 ATS.OR.127(a),
// 02 F4 as a consumer must show it): every aircraft manned-feed serves
// the console, at its last position with its age, live, stale, its
// source disabled (by whom) or delivered late, relevant aircraft apart
// from the rest; the active restrictions under them; and the stream's
// console/status/v1 in a status bar of its own: adapters[], degraded[],
// dropped_frames, cis_age_s, policy_version and the thresholds as the
// frame gives them (INV-03: none is defaulted here). An empty picture
// says why it is empty (SC-22); a stream that stopped says since when,
// and the aircraft it last sent stay on the map with their ages, never
// moved and never called lost (B-13, C-12).
import { useCallback, useMemo } from "react";
import { fmtAge, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { subscribeFrame, useNowMs } from "@rootxkit/uspace-ui/live";
import { useBBoxSubscription } from "@rootxkit/uspace-ui/map";
import { DegradedBanner, FeedStatusBar } from "@rootxkit/uspace-ui/status";
import { trackIconParts } from "@rootxkit/uspace-ui/symbology";
import { toView } from "./adapt";
import { ConsoleMap } from "./ConsoleMap";
import { useConsole } from "./context";
import { compareShown, drawnOf, type Aircraft, type Drawn } from "./manned";
import { MannedLayer, STATE_TOKEN, type MannedFeature } from "./MannedLayer";
import { adaptersLine, adapterText, altitudeText, identText, labelText, motionText, stateText, symbolOf } from "./picture";
import { streamSilent, type StreamStatus } from "./stream";
import { Empty, timesShown } from "./ui";
import { useMannedStream } from "./useManned";
import { useRestrictions } from "./useRestrictions";

/** How often ages are redrawn. Display-only. */
const TICK_MS = 1000;
/** Rows of the aircraft list; the map shows every aircraft. Display-only. */
export const LIST_ROWS = 200;
/** The bbox subscription's margin, settle time and grid (05 §5). Display-only. */
const BBOX = { marginFraction: 0.25, debounceMs: 500, quantizeDeg: 0.05 } as const;

/** The kit's surveillance symbol, in the drawn state's colour, rotated by the track as sent. */
export function AircraftSymbol({ a, d }: { a: Aircraft; d: Drawn }) {
  const parts = trackIconParts("surveillance", a.trackDeg !== null);
  const colour = `var(${STATE_TOKEN[d.state]})`;
  return (
    <svg
      viewBox="0 0 56 56"
      width={a.relevant === true ? 22 : 16}
      height={a.relevant === true ? 22 : 16}
      aria-hidden="true"
      data-testid="aircraft-symbol"
      data-symbol={symbolOf(a, d)}
      style={{ transform: `rotate(${a.trackDeg ?? 0}deg)`, opacity: d.state === "live" ? 1 : d.state === "backlog" ? 0.9 : 0.55 }}
    >
      {parts.map((p, i) => (
        <path
          key={i}
          d={p.d}
          fill={p.fill ? colour : "none"}
          stroke={colour}
          strokeWidth={p.strokeWidth}
          {...(p.dash === null ? {} : { strokeDasharray: p.dash })}
        />
      ))}
    </svg>
  );
}

function SubscribeOnView({ send }: { send: (bbox: [number, number, number, number]) => void }) {
  useBBoxSubscription({ ...BBOX, onChange: (b) => send([b.minLng, b.minLat, b.maxLng, b.maxLat]) });
  return null;
}

/** The picture's status bar: the manned stream's own console/status/v1. */
export function PictureStatus({ status, nowMs, counters }: { status: StreamStatus; nowMs: number; counters: { refused: number; outOfOrder: number; evicted: number } }) {
  const t = useT();
  const { lang } = useLang();
  const silent = streamSilent(status, nowMs);
  return (
    <section
      aria-label={t("ansp.picture.status.label")}
      data-testid="picture-status"
      data-connection={status.connection}
      data-silent={silent}
      className="flex flex-col gap-1 rounded border border-[var(--us-border)] bg-[var(--us-surface-sunken)] p-2 text-xs"
    >
      <FeedStatusBar status={status} nowMs={nowMs} />
      {status.connection === "down" && (
        <p role="alert" className="m-0 font-semibold text-[var(--us-danger)]" data-testid="picture-down">
          {t("ansp.picture.status.down", timesShown({ since: new Date(status.sinceMs).toISOString() }, lang))}
        </p>
      )}
      {status.refused !== null && <p className="m-0 text-[var(--us-danger)]">{t("ansp.picture.status.refused", { reason: status.refused })}</p>}
      {silent && status.lastStatusAtMs !== null && (
        <p role="alert" className="m-0 font-semibold text-[var(--us-danger)]" data-testid="picture-silent">
          {t("ansp.picture.status.silent", { age: fmtAge((nowMs - status.lastStatusAtMs) / 1000, lang), threshold: status.staleAfterS ?? "—" })}
        </p>
      )}
      {status.policyVersion !== null && (
        <p className="m-0" data-testid="picture-policy">
          {t("ansp.picture.status.policy", {
            version: status.policyVersion,
            stale: status.staleAfterS ?? "—",
            live: status.liveMaxAgeS ?? "—",
          })}
        </p>
      )}
      {status.connection === "live" && (
        <p className="m-0" data-testid="picture-cis">
          {status.cisVersion === null
            ? t("ansp.picture.status.cis_none")
            : t("ansp.picture.status.cis", { version: status.cisVersion, age: status.cisAgeS === null ? "—" : Math.round(status.cisAgeS) })}
          {status.nats !== null && <span> · {t("ansp.status.nats", { state: status.nats })}</span>}
          {status.relevance !== null && <span> · {t("ansp.picture.status.relevance", { text: status.relevance })}</span>}
        </p>
      )}
      {status.connection === "live" && <DegradedBanner degraded={status.degraded} cisAgeS={status.cisAgeS} />}
      {status.adapters !== null && (
        <ul className="m-0 flex flex-wrap gap-x-4 gap-y-0.5 p-0" data-testid="picture-adapters" aria-label={t("ansp.picture.status.adapters")}>
          {status.adapters.length === 0 && <li className="list-none">{t("ansp.picture.adapters_none")}</li>}
          {status.adapters.map((a) => (
            <li
              key={a.id}
              className={`list-none ${a.state === "live" ? "" : "font-semibold text-[var(--us-danger)]"}`}
              data-adapter={a.id}
              data-state={a.state}
            >
              {adapterText(a, status.sources, t, lang)}
            </li>
          ))}
        </ul>
      )}
      {(counters.refused > 0 || counters.outOfOrder > 0 || counters.evicted > 0 || status.adaptersMalformed > 0) && (
        <p className="m-0 text-[var(--us-text-muted)]" data-testid="picture-counters">
          {t("ansp.picture.status.counters", {
            refused: counters.refused,
            out_of_order: counters.outOfOrder,
            evicted: counters.evicted,
            adapters: status.adaptersMalformed,
          })}
        </p>
      )}
    </section>
  );
}

export function PicturePage() {
  const t = useT();
  const { lang } = useLang();
  const { markSignedOut } = useConsole();
  const stream = useMannedStream(markSignedOut);
  const nowMs = useNowMs(TICK_MS);
  const restrictions = useRestrictions("active");
  const views = useMemo(() => (restrictions.restrictions ?? []).map((r) => toView(r, lang)), [restrictions.restrictions, lang]);
  const { status, aircraft } = stream;
  const { send } = stream;
  const onBBox = useCallback((bbox: [number, number, number, number]) => send(subscribeFrame(bbox, ["manned"])), [send]);

  const shown = useMemo(
    () =>
      [...aircraft.values()]
        .map((a) => ({ a, d: drawnOf(a, nowMs, status.staleAfterS, status.clockOffsetMs) }))
        .sort(compareShown),
    [aircraft, nowMs, status.staleAfterS, status.clockOffsetMs],
  );
  const features = useMemo<MannedFeature[]>(
    () =>
      shown.map(({ a, d }) => ({
        icao24: a.icao24,
        lng: a.lng,
        lat: a.lat,
        state: d.state,
        relevant: a.relevant,
        trackDeg: a.trackDeg,
        label: labelText(a, d, status.sources, status.staleAfterS, t, lang),
      })),
    [shown, status.sources, status.staleAfterS, t, lang],
  );
  const relevant = shown.filter((x) => x.a.relevant === true).length;

  return (
    <div className="flex flex-col gap-3">
      <h2 className="m-0 text-lg font-semibold">{t("ansp.picture.title")}</h2>
      <PictureStatus status={status} nowMs={nowMs} counters={stream.picture.counters} />
      {status.connection !== "live" && shown.length > 0 && (
        <p role="alert" className="m-0 text-sm font-semibold text-[var(--us-danger)]" data-testid="picture-held">
          {t("ansp.picture.held", { count: shown.length })}
        </p>
      )}
      <div className="flex flex-col gap-3 lg:flex-row">
        <div className="flex flex-col gap-1 lg:w-[60%]">
          <ConsoleMap restrictions={views} className="h-[65vh]">
            <MannedLayer aircraft={features} />
            <SubscribeOnView send={onBBox} />
          </ConsoleMap>
          <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.picture.map_note")}</p>
        </div>
        <div className="flex flex-1 flex-col gap-2">
          {shown.length === 0 &&
            (status.connection === "live" ? (
              <Empty textKey="ansp.picture.empty" vars={{ adapters: adaptersLine(status, t, lang) }} testId="picture-empty" />
            ) : status.connection === "down" ? (
              <Empty
                textKey="ansp.picture.unavailable"
                vars={timesShown({ since: new Date(status.sinceMs).toISOString() }, lang)}
                testId="picture-unavailable"
              />
            ) : (
              <Empty textKey="ansp.picture.connecting" testId="picture-connecting" />
            ))}
          {shown.length > 0 && (
            <>
              <p className="m-0 text-xs" data-testid="picture-count">
                {t("ansp.picture.count", { count: shown.length, relevant })}
              </p>
              <ul className="m-0 flex flex-col gap-1 p-0" data-testid="aircraft-list">
                {shown.slice(0, LIST_ROWS).map(({ a, d }) => (
                  <li
                    key={a.icao24}
                    className={`flex list-none items-start gap-2 rounded border p-1.5 text-xs ${a.relevant === true ? "border-[var(--us-border-strong)]" : "border-[var(--us-border)] opacity-80"}`}
                    data-aircraft={a.icao24}
                    data-state={d.state}
                    data-relevant={a.relevant === null ? "unstated" : String(a.relevant)}
                  >
                    <AircraftSymbol a={a} d={d} />
                    <div className="flex flex-col">
                      <span className="font-semibold">{identText(a)}</span>
                      <span data-testid="aircraft-altitude">{altitudeText(a, t, lang)}</span>
                      <span>{motionText(a, lang)}</span>
                      <span
                        data-testid="aircraft-state"
                        className={d.state === "live" ? "" : "font-semibold text-[var(--us-danger)]"}
                      >
                        {stateText(a, d, status.sources, status.staleAfterS, t, lang)}
                      </span>
                      <span className="text-[var(--us-text-muted)]">
                        {t(`ansp.picture.relevance.${a.relevant === null ? "unstated" : a.relevant ? "relevant" : "other"}`)} · {a.sourceInstance}
                        {a.emergency === true && <strong className="ms-1 text-[var(--us-danger)]">{t("ansp.picture.emergency")}</strong>}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
              {shown.length > LIST_ROWS && <p className="m-0 text-xs">{t("ansp.picture.more", { count: shown.length - LIST_ROWS })}</p>}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
