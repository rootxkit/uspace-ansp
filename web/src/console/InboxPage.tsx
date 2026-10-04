"use client";

// /<locale>/inbox: the Annex V coordination inbox (2021/664 Art. 13(2);
// 01 N3). Escalated notices first and loudest, then those awaiting a
// person's acknowledgement, then the informational ones (intent_notice,
// ended: no acknowledgement required) and the acknowledged ones. A
// notice shows its kind, sender, intents with their authorisation
// numbers and windows, the restrictions it touches (the API's
// restriction_ids) and its volumes on the map; a watch supervisor
// acknowledges it with an optional note, and the API records the role,
// never a name. A notice acknowledged elsewhere first answers 409: the
// list is read again and says so. Live through the coordination stream;
// a browser notification for each escalation is opt-in.
import Link from "next/link";
import { useMemo, useState } from "react";
import type { GeoJSONSource, Map as MapLibreMap } from "maplibre-gl";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { resolveColour, useLayer } from "@rootxkit/uspace-ui/layers";
import { useNowMs } from "@rootxkit/uspace-ui/live";
import { FeedStatusBar } from "@rootxkit/uspace-ui/status";
import { Button, Label, Textarea } from "@rootxkit/uspace-ui/ui";
import { failureOf, type CallFailure } from "../api/client";
import { toView } from "./adapt";
import { ConsoleMap } from "./ConsoleMap";
import { useConsole } from "./context";
import {
  acknowledgeBody,
  groupOf,
  GROUP_ORDER,
  intentsOf,
  NOTE_MAX_BYTES,
  noteBytes,
  ordered,
  volumesOf,
  type ApiNotice,
  type Group,
} from "./inbox";
import { useInbox } from "./InboxProvider";
import { maySupervise } from "./roles";
import { Empty, Loading, ProblemNotice, Time } from "./ui";
import { useRestrictions } from "./useRestrictions";

const FILTERS = ["all", "escalated", "received", "acknowledged"] as const;
type Filter = (typeof FILTERS)[number];
const NOTICE_LAYER = "ansp-notices";
/** How often ages on the stream line are redrawn. Display-only. */
const TICK_MS = 1000;

function NoticeLayer({ features }: { features: GeoJSON.Feature[] }) {
  const data = useMemo<GeoJSON.FeatureCollection>(() => ({ type: "FeatureCollection", features }), [features]);
  useLayer<GeoJSON.FeatureCollection>({
    id: NOTICE_LAYER,
    data,
    build(map: MapLibreMap) {
      const colour = resolveColour(map, "--us-severity-warning");
      const strong = resolveColour(map, "--us-danger");
      map.addSource(NOTICE_LAYER, { type: "geojson", data: { type: "FeatureCollection", features: [] } });
      map.addLayer({
        id: `${NOTICE_LAYER}-fill`,
        type: "fill",
        source: NOTICE_LAYER,
        filter: ["==", ["geometry-type"], "Polygon"],
        paint: { "fill-color": ["case", ["get", "emphasised"], strong, colour], "fill-opacity": ["case", ["get", "emphasised"], 0.3, 0.12] },
      });
      map.addLayer({
        id: `${NOTICE_LAYER}-line`,
        type: "line",
        source: NOTICE_LAYER,
        filter: ["==", ["geometry-type"], "Polygon"],
        paint: { "line-color": ["case", ["get", "emphasised"], strong, colour], "line-width": ["case", ["get", "emphasised"], 3, 1.5], "line-dasharray": [3, 2] },
      });
      map.addLayer({
        id: `${NOTICE_LAYER}-centre`,
        type: "circle",
        source: NOTICE_LAYER,
        filter: ["==", ["geometry-type"], "Point"],
        paint: { "circle-radius": 6, "circle-color": ["case", ["get", "emphasised"], strong, colour], "circle-stroke-width": 1, "circle-stroke-color": "#ffffff" },
      });
      return [`${NOTICE_LAYER}-fill`, `${NOTICE_LAYER}-line`, `${NOTICE_LAYER}-centre`];
    },
    update(map: MapLibreMap, d: GeoJSON.FeatureCollection) {
      (map.getSource(NOTICE_LAYER) as GeoJSONSource | undefined)?.setData(d);
    },
  });
  return null;
}

function Acknowledge({ notice }: { notice: ApiNotice }) {
  const t = useT();
  const { client } = useConsole();
  const { put, reload } = useInbox();
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<CallFailure | null>(null);
  const bytes = noteBytes(note);
  const tooLong = bytes > NOTE_MAX_BYTES;
  const submit = async () => {
    setBusy(true);
    setFailure(null);
    try {
      const { data } = await client.POST("/v1/coordination/inbox/{id}/acknowledge", {
        params: { path: { id: notice.ack_id } },
        body: acknowledgeBody(note),
      });
      if (data !== undefined) put(data);
      setNote("");
    } catch (err: unknown) {
      const f = failureOf(err);
      setFailure(f);
      // Acknowledged by someone else first (409) or gone (404): a
      // permanent answer, never retried; the inbox is read again.
      if (f.status === 409 || f.status === 404) reload();
    } finally {
      setBusy(false);
    }
  };
  const id = `note-${notice.ack_id}`;
  return (
    <div className="flex flex-col gap-1" data-testid="acknowledge-form">
      <Label htmlFor={id}>{t("ansp.inbox.note")}</Label>
      <Textarea id={id} rows={2} value={note} onChange={(e) => setNote(e.target.value)} data-testid="ack-note" />
      <p className={`m-0 text-xs ${tooLong ? "text-[var(--us-danger)]" : "text-[var(--us-text-muted)]"}`}>
        {t("ansp.inbox.note_bytes", { bytes, max: NOTE_MAX_BYTES })}
      </p>
      <div>
        <Button type="button" size="sm" disabled={busy || tooLong} onClick={() => void submit()} data-testid="ack-submit">
          {t("ansp.inbox.acknowledge")}
        </Button>
      </div>
      {failure !== null && failure.status === 409 && (
        <p role="status" className="m-0 text-xs font-semibold" data-testid="ack-conflict">
          {t("ansp.inbox.ack_conflict")}
        </p>
      )}
      {failure !== null && <ProblemNotice failure={failure} />}
    </div>
  );
}

function NoticeCard({ notice, selected, onSelect }: { notice: ApiNotice; selected: boolean; onSelect(): void }) {
  const t = useT();
  const { lang } = useLang();
  const { role } = useConsole();
  const group = groupOf(notice);
  const { intents, malformed } = intentsOf(notice.payload);
  const loud = group === "escalated";
  return (
    <li
      className={`flex list-none flex-col gap-1 rounded border p-2 text-sm ${loud ? "border-2 border-[var(--us-danger)] bg-[var(--us-surface-raised)]" : "border-[var(--us-border)]"} ${selected ? "outline outline-2 outline-[var(--us-focus)]" : ""}`}
      data-testid="notice"
      data-ack={notice.ack_id}
      data-state={notice.state}
      data-group={group}
      data-kind={notice.kind}
      {...(loud ? { role: "alert" } : {})}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className={`m-0 font-semibold ${loud ? "text-[var(--us-danger)]" : ""}`}>
          {t(`ansp.inbox.kind.${notice.kind}`)} · {t(`ansp.inbox.state.${notice.state}`)}
        </p>
        <Button type="button" size="sm" variant="outline" onClick={onSelect} data-testid="notice-show">
          {t("ansp.inbox.show_on_map")}
        </Button>
      </div>
      <p className="m-0">{t("ansp.inbox.sender", { ussp: notice.ussp_id, client: notice.sender_client_id, ref: notice.notice_ref })}</p>
      <p className="m-0 text-xs">
        {t("ansp.inbox.received")} <Time iso={notice.received_at} />
      </p>
      {loud && (
        <p className="m-0 font-semibold text-[var(--us-danger)]" data-testid="notice-escalated">
          {t("ansp.inbox.escalated", { count: notice.escalations ?? 1 })} <Time iso={notice.last_escalated_at ?? notice.escalated_at} />
        </p>
      )}
      {group === "informational" && <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.inbox.informational")}</p>}
      {notice.sender_unverified === true && (
        <p className="m-0 text-xs font-semibold text-[var(--us-danger)]">{t("ansp.inbox.sender_unverified")}</p>
      )}
      {intents.length > 0 && (
        <table className="text-xs">
          <thead>
            <tr>
              <th className="pe-2 text-start">{t("ansp.inbox.col.intent")}</th>
              <th className="pe-2 text-start">{t("ansp.inbox.col.authorisation")}</th>
              <th className="pe-2 text-start">{t("ansp.inbox.col.intent_state")}</th>
              <th className="text-start">{t("ansp.inbox.col.window")}</th>
            </tr>
          </thead>
          <tbody>
            {intents.map((i) => (
              <tr key={i.intentRef}>
                <td className="pe-2 font-mono">{i.intentRef}</td>
                <td className="pe-2 font-mono">{i.authorisationNumber}</td>
                <td className="pe-2">{i.state}</td>
                <td>
                  <Time iso={i.timeStart} /> – <Time iso={i.timeEnd} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {intents.length === 0 && (
        <p className="m-0 text-xs">
          {t("ansp.inbox.authorisations", { list: notice.authorisation_numbers.join(", ") || "—" })} ·{" "}
          {t("ansp.inbox.intents", { list: notice.intent_refs.join(", ") || "—" })}
        </p>
      )}
      {malformed > 0 && <p className="m-0 text-xs">{t("ansp.inbox.intents_malformed", { count: malformed })}</p>}
      <p className="m-0 text-xs" data-testid="notice-restrictions">
        {(notice.restriction_ids ?? []).length === 0 ? (
          t("ansp.inbox.restrictions_none")
        ) : (
          <>
            {t("ansp.inbox.restrictions")}{" "}
            {(notice.restriction_ids ?? []).map((id, i) => (
              <span key={id}>
                {i > 0 && ", "}
                <Link href={`/${lang}/restrictions/${id}`} className="font-mono underline">
                  {id}
                </Link>
              </span>
            ))}
          </>
        )}
      </p>
      {notice.state === "acknowledged" ? (
        <p className="m-0 text-xs" data-testid="notice-acknowledged">
          {t("ansp.inbox.acknowledged_by", { role: notice.acknowledged_by === undefined ? "—" : t(`ansp.role.${notice.acknowledged_by}`) })}{" "}
          <Time iso={notice.acknowledged_at} />
          {notice.acknowledgement_note !== undefined && notice.acknowledgement_note !== "" && (
            <span className="block">{t("ansp.inbox.acknowledged_note", { note: notice.acknowledgement_note })}</span>
          )}
        </p>
      ) : maySupervise(role) ? (
        <Acknowledge notice={notice} />
      ) : (
        <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.inbox.ack_role")}</p>
      )}
    </li>
  );
}

function NotifyControl() {
  const t = useT();
  const { notify, setNotify } = useInbox();
  if (notify === "unsupported" || notify === "denied") {
    return <p className="m-0 text-xs text-[var(--us-text-muted)]">{t(`ansp.inbox.notify.${notify}`)}</p>;
  }
  return (
    <Button type="button" size="sm" variant="outline" onClick={() => setNotify(notify !== "on")} data-testid="notify-toggle" data-notify={notify}>
      {t(notify === "on" ? "ansp.inbox.notify.stop" : "ansp.inbox.notify.start")}
    </Button>
  );
}

export function InboxPage() {
  const t = useT();
  const { lang } = useLang();
  const inbox = useInbox();
  const nowMs = useNowMs(TICK_MS);
  const [filter, setFilter] = useState<Filter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  const restrictions = useRestrictions(null);
  const views = useMemo(
    () => (restrictions.restrictions ?? []).filter((r) => r.state === "active" || r.state === "planned").map((r) => toView(r, lang)),
    [restrictions.restrictions, lang],
  );
  const list = useMemo(() => ordered(inbox.notices.values()).filter((n) => filter === "all" || n.state === filter), [inbox.notices, filter]);
  const groups = useMemo(() => {
    const m = new Map<Group, ApiNotice[]>();
    for (const n of list) {
      const g = groupOf(n);
      m.set(g, [...(m.get(g) ?? []), n]);
    }
    return GROUP_ORDER.filter((g) => m.has(g)).map((g) => ({ group: g, notices: m.get(g) ?? [] }));
  }, [list]);
  const volumes = useMemo(() => {
    const each = list.filter((n) => n.state !== "acknowledged" || n.ack_id === selected).map((n) => volumesOf(n.ack_id, n.payload, n.ack_id === selected));
    return {
      features: each.flatMap((v) => v.features),
      circles: each.reduce((sum, v) => sum + v.circles, 0),
      malformed: each.reduce((sum, v) => sum + v.malformed, 0),
    };
  }, [list, selected]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="m-0 text-lg font-semibold">{t("ansp.inbox.title")}</h2>
        <NotifyControl />
      </div>
      <section aria-label={t("ansp.inbox.stream")} data-testid="inbox-stream" data-connection={inbox.feed.connection} className="text-xs">
        <FeedStatusBar status={inbox.feed} nowMs={nowMs} />
        {inbox.feed.connection === "down" && <p className="m-0 mt-1 font-semibold text-[var(--us-danger)]">{t("ansp.inbox.stream_down")}</p>}
      </section>
      <label className="flex items-center gap-2 text-sm">
        {t("ansp.inbox.filter")}
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value as Filter)}
          className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1"
          data-testid="inbox-filter"
        >
          {FILTERS.map((f) => (
            <option key={f} value={f}>
              {t(`ansp.inbox.filter.${f}`)}
            </option>
          ))}
        </select>
      </label>
      {inbox.failure !== null && <ProblemNotice failure={inbox.failure} />}
      {inbox.truncated && <p className="m-0 text-xs">{t("ansp.inbox.truncated")}</p>}
      {(inbox.dropped > 0 || inbox.ignored > 0) && (
        <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.inbox.counters", { dropped: inbox.dropped, ignored: inbox.ignored })}</p>
      )}
      <div className="flex flex-col gap-3 lg:flex-row">
        <div className="flex flex-1 flex-col gap-3" data-testid="inbox">
          {!inbox.loaded && inbox.failure === null && <Loading />}
          {inbox.loaded && list.length === 0 && (
            <Empty textKey={filter === "all" ? "ansp.inbox.none" : "ansp.inbox.none_in_state"} vars={{ state: t(`ansp.inbox.filter.${filter}`) }} testId="inbox-none" />
          )}
          {groups.map(({ group, notices }) => (
            <section key={group} className="flex flex-col gap-2" data-testid={`inbox-group-${group}`}>
              <h3 className={`m-0 text-base font-semibold ${group === "escalated" ? "text-[var(--us-danger)]" : ""}`}>
                {t(`ansp.inbox.group.${group}`, { count: notices.length })}
              </h3>
              <ul className="m-0 flex flex-col gap-2 p-0">
                {notices.map((n) => (
                  <NoticeCard key={n.ack_id} notice={n} selected={n.ack_id === selected} onSelect={() => setSelected(n.ack_id)} />
                ))}
              </ul>
            </section>
          ))}
        </div>
        <div className="flex flex-col gap-1 lg:w-[40%]">
          <ConsoleMap restrictions={views} className="h-[60vh]">
            <NoticeLayer features={volumes.features} />
          </ConsoleMap>
          <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.inbox.map_note")}</p>
          {volumes.circles > 0 && <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.inbox.circles", { count: volumes.circles })}</p>}
          {volumes.malformed > 0 && <p className="m-0 text-xs">{t("ansp.inbox.volumes_malformed", { count: volumes.malformed })}</p>}
        </div>
      </div>
    </div>
  );
}
