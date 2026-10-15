"use client";

// /<locale>/overview: the page after sign-in. A row of key figures, each
// counted from what the console already reads through the BFF (the
// restriction list and the delivery alarms, live on the restriction
// stream; the coordination inbox, live on its stream; the adapters and
// the source switches, read again every READ_PERIOD_MS), then the map of
// the restrictions in force or planned, the open alarms, the notices
// awaiting a person, the newest restrictions and the surveillance
// sources. The tiles of src/console/OverviewTiles.tsx read the API's
// summaries, each for the role that may read it. Each figure says what
// it counts and an unknown one is a dash, never a zero; the API's
// failures are shown beside them (E-02). Nothing here is judged: a tone
// repeats a state the API stated.
import Link from "next/link";
import { useEffect, useMemo } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { useNowMs } from "@rootxkit/uspace-ui/live";
import { FeedStatusBar } from "@rootxkit/uspace-ui/status";
import type { StatusTone } from "@rootxkit/uspace-ui/theme";
import { Button, KpiRow, MapPanel, Panel, StatTile, StatusBadge } from "@rootxkit/uspace-ui/ui";
import { AdapterIcon, AlarmIcon, ClockIcon, InboxIcon, RestrictionIcon } from "../components/icons";
import { toView } from "./adapt";
import { statusLine, switchFor, type ApiAdapter } from "./adapters";
import { ConsoleMap } from "./ConsoleMap";
import { useConsole, useLoad } from "./context";
import { awaitingCount, groupOf, ordered } from "./inbox";
import { useInbox } from "./InboxProvider";
import { adapterCounts, openAlarms, recentRestrictions, restrictionCounts, switchesOff } from "./overview";
import { OccurrencesTile, RequestsTile, UsersTile } from "./OverviewTiles";
import { mayAdminister, maySupervise } from "./roles";
import { ConsolePageHeader, Empty, Loading, ProblemNotice, StateBadge, Time, timesShown } from "./ui";
import { useRestrictions } from "./useRestrictions";

/** How often the adapters and switches are read again. Display-only. */
export const READ_PERIOD_MS = 10_000;
/** How many items each list panel shows; each links its whole page. Display-only. */
export const PANEL_ROWS = 5;
/** How often ages are redrawn. Display-only. */
const TICK_MS = 1000;

/** The kit's tone per adapter status: it repeats the status the line states. */
const ADAPTER_TONE: Readonly<Record<ApiAdapter["status"], StatusTone>> = {
  running: "ok",
  configured: "neutral",
  silent: "warning",
  disabled: "critical",
};

export function OverviewPage() {
  const t = useT();
  const { lang } = useLang();
  const { role, feed } = useConsole();
  const inbox = useInbox();
  const nowMs = useNowMs(TICK_MS);
  const live = useRestrictions(null);
  const adapters = useLoad(async (c) => (await c.GET("/v1/adapters")).data?.adapters ?? [], "adapters");
  const sources = useLoad(async (c) => (await c.GET("/v1/sources")).data?.sources ?? [], "sources");
  const { reload: reloadAdapters } = adapters;
  const { reload: reloadSources } = sources;
  useEffect(() => {
    const id = setInterval(() => {
      reloadAdapters();
      reloadSources();
    }, READ_PERIOD_MS);
    return () => clearInterval(id);
  }, [reloadAdapters, reloadSources]);

  const list = live.restrictions;
  const counts = list === null ? null : restrictionCounts(list);
  const alarms = openAlarms(live.alarms);
  const unacknowledged = alarms.filter((a) => a.state === "open").length;
  const waiting = awaitingCount(inbox.notices.values());
  const awaitingTotal = waiting.escalated + waiting.awaiting;
  const awaitingNotices = useMemo(
    () => ordered(inbox.notices.values()).filter((n) => groupOf(n) === "escalated" || groupOf(n) === "awaiting"),
    [inbox.notices],
  );
  const byAdapter = adapters.data === null ? null : adapterCounts(adapters.data);
  const off = sources.data === null ? null : switchesOff(sources.data);
  const views = useMemo(
    () => (list ?? []).filter((r) => r.state === "active" || r.state === "planned").map((r) => toView(r, lang)),
    [list, lang],
  );
  const identifierOf = useMemo(() => new Map((list ?? []).map((r) => [r.id, r.identifier])), [list]);
  const recent = list === null ? [] : recentRestrictions(list, PANEL_ROWS);
  const truncatedHint = live.truncated ? t("ansp.overview.truncated") : undefined;

  return (
    <div className="flex flex-col gap-6" data-testid="overview">
      <ConsolePageHeader
        titleKey="ansp.overview.title"
        descriptionKey="ansp.overview.description"
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <Link href={`/${lang}/picture`}>{t("ansp.overview.open_picture")}</Link>
            </Button>
            {maySupervise(role) && (
              <Button asChild size="sm">
                <Link href={`/${lang}/restrictions/new`} data-testid="overview-plan">
                  {t("ansp.nav.plan")}
                </Link>
              </Button>
            )}
          </>
        }
      />

      <KpiRow label={t("ansp.overview.kpis")}>
        <div data-testid="kpi-active" data-value={counts?.active ?? ""}>
          <StatTile
            className="h-full"
            icon={<RestrictionIcon />}
            label={t("ansp.overview.kpi.active")}
            value={counts === null ? null : counts.active}
            hint={counts === null ? undefined : t("ansp.overview.kpi.active_hint", { planned: counts.planned })}
            {...(truncatedHint === undefined ? {} : { status: { tone: "info" as const, label: truncatedHint } })}
          />
        </div>
        <div data-testid="kpi-alarms" data-value={live.alarmsFailure === null && list !== null ? alarms.length : ""}>
          <StatTile
            className="h-full"
            icon={<AlarmIcon />}
            label={t("ansp.overview.kpi.alarms")}
            value={live.alarmsFailure !== null || list === null ? null : alarms.length}
            status={
              alarms.length > 0
                ? { tone: "critical", label: t("ansp.overview.kpi.alarms_open", { count: unacknowledged }) }
                : { tone: "ok", label: t("ansp.overview.kpi.alarms_none") }
            }
            hint={t("ansp.overview.kpi.alarms_hint")}
          />
        </div>
        <div data-testid="kpi-awaiting" data-value={inbox.loaded ? awaitingTotal : ""}>
          <StatTile
            className="h-full"
            icon={<InboxIcon />}
            label={t("ansp.overview.kpi.awaiting")}
            value={inbox.loaded ? awaitingTotal : null}
            {...(inbox.loaded
              ? {
                  status:
                    waiting.escalated > 0
                      ? { tone: "critical" as const, label: t("ansp.overview.kpi.escalated", { count: waiting.escalated }) }
                      : awaitingTotal > 0
                        ? { tone: "warning" as const, label: t("ansp.overview.kpi.awaiting_some") }
                        : { tone: "ok" as const, label: t("ansp.overview.kpi.awaiting_none") },
                }
              : {})}
            hint={t(`ansp.status.coordination.${inbox.feed.connection}`, timesShown({ since: new Date(inbox.feed.sinceMs).toISOString() }, lang))}
          />
        </div>
        <div data-testid="kpi-adapters" data-value={byAdapter === null ? "" : byAdapter.running}>
          <StatTile
            className="h-full"
            icon={<AdapterIcon />}
            label={t("ansp.overview.kpi.adapters")}
            value={byAdapter === null ? null : t("ansp.overview.kpi.adapters_value", { running: byAdapter.running, total: byAdapter.total })}
            {...(byAdapter === null
              ? {}
              : {
                  status:
                    byAdapter.disabled + byAdapter.silent > 0
                      ? {
                          tone: "warning" as const,
                          label: t("ansp.overview.kpi.adapters_attention", { silent: byAdapter.silent, disabled: byAdapter.disabled }),
                        }
                      : { tone: "ok" as const, label: t("ansp.overview.kpi.adapters_all") },
                })}
            {...(off === null ? {} : { hint: t("ansp.overview.kpi.switches_off", { count: off }) })}
          />
        </div>
        <div data-testid="kpi-cis" data-value={live.cisAgeS === null ? "" : Math.round(live.cisAgeS)}>
          <StatTile
            className="h-full"
            icon={<ClockIcon />}
            label={t("ansp.overview.kpi.cis")}
            value={live.cisAgeS === null ? null : Math.round(live.cisAgeS)}
            unit={t("ansp.overview.unit.s")}
            hint={live.cisVersion === null ? t("ansp.status.cis_none") : t("ansp.overview.kpi.cis_version", { version: live.cisVersion })}
          />
        </div>
        {maySupervise(role) && <RequestsTile />}
        {maySupervise(role) && <OccurrencesTile />}
        {mayAdminister(role) && <UsersTile />}
      </KpiRow>

      {live.failure !== null && <ProblemNotice failure={live.failure} />}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_28rem]">
        <MapPanel
          title={t("ansp.overview.map_title")}
          description={t("ansp.overview.map_description", { count: views.length })}
          mapClassName="h-[28rem]"
          actions={
            <Button asChild variant="outline" size="sm">
              <Link href={`/${lang}/restrictions`}>{t("ansp.overview.all_restrictions")}</Link>
            </Button>
          }
        >
          <ConsoleMap restrictions={views} fill />
        </MapPanel>

        <Panel
          title={t("ansp.overview.alarms_title")}
          description={t("ansp.overview.alarms_description")}
          data-testid="overview-alarms"
          actions={
            alarms.length > 0 ? <StatusBadge tone="critical">{t("ansp.overview.kpi.alarms_open", { count: unacknowledged })}</StatusBadge> : undefined
          }
        >
          {live.alarmsFailure !== null && <ProblemNotice failure={live.alarmsFailure} />}
          {list === null && live.alarmsFailure === null && <Loading />}
          {list !== null && alarms.length === 0 && live.alarmsFailure === null && <Empty textKey="ansp.alarms.none" testId="overview-alarms-none" />}
          {alarms.length > 0 && (
            <ul className="m-0 flex list-none flex-col p-0">
              {alarms.slice(0, PANEL_ROWS).map((a) => {
                const ident = a.restriction_id === undefined ? undefined : identifierOf.get(a.restriction_id);
                return (
                  <li key={a.id} className="flex flex-col gap-0.5 border-b border-border py-2.5 text-sm last:border-b-0" data-kind={a.kind} data-state={a.state}>
                    <span className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-semibold text-status-critical">{t(`ansp.alarm.kind.${a.kind}`)}</span>
                      <StatusBadge tone={a.state === "open" ? "critical" : "warning"} variant="outline">
                        {t(`ansp.alarm.state.${a.state}`)}
                      </StatusBadge>
                    </span>
                    {a.restriction_id !== undefined && (
                      <Link href={`/${lang}/restrictions/${a.restriction_id}`} className="font-mono text-xs underline underline-offset-2">
                        {ident ?? a.restriction_id}
                      </Link>
                    )}
                    <span className="text-xs text-muted-foreground">{t("ansp.alarm.since", timesShown({ since: a.since }, lang))}</span>
                  </li>
                );
              })}
            </ul>
          )}
          {alarms.length > PANEL_ROWS && (
            <p className="m-0 pt-2 text-xs text-muted-foreground">{t("ansp.overview.more", { count: alarms.length - PANEL_ROWS })}</p>
          )}
        </Panel>
      </div>

      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_28rem]">
        <div className="grid content-start gap-6">
          <Panel
            title={t("ansp.overview.recent_title")}
            description={t("ansp.overview.recent_description")}
            padding="none"
            actions={
              <Button asChild variant="ghost" size="sm">
                <Link href={`/${lang}/restrictions`}>{t("ansp.overview.view_all")}</Link>
              </Button>
            }
          >
            {list === null && live.failure === null && (
              <div className="p-4">
                <Loading />
              </div>
            )}
            {list !== null && recent.length === 0 && (
              <div className="p-4">
                <Empty textKey="ansp.restrictions.none" testId="overview-recent-none" />
              </div>
            )}
            {recent.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-sm" data-testid="overview-recent">
                  <thead>
                    <tr className="border-b border-border bg-panel-header text-xs text-muted-foreground">
                      <th className="px-4 py-2 text-start font-semibold">{t("ansp.restrictions.col.identifier")}</th>
                      <th className="px-4 py-2 text-start font-semibold">{t("ansp.restrictions.col.state")}</th>
                      <th className="px-4 py-2 text-start font-semibold">{t("ansp.restrictions.col.window")}</th>
                      <th className="px-4 py-2 text-start font-semibold">{t("ansp.restrictions.col.airspace")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recent.map((r) => (
                      <tr key={r.id} className="border-b border-border last:border-b-0 hover:bg-hover" data-restriction={r.identifier} data-state={r.state}>
                        <td className="px-4 py-2.5">
                          <Link href={`/${lang}/restrictions/${r.id}`} className="font-mono font-semibold underline underline-offset-2">
                            {r.identifier}
                          </Link>
                        </td>
                        <td className="px-4 py-2.5">
                          <StateBadge state={r.state} />
                        </td>
                        <td className="px-4 py-2.5 text-xs">
                          <Time iso={r.starts_at} /> – <Time iso={r.ends_at} />
                        </td>
                        <td className="px-4 py-2.5 font-mono text-xs">{r.uspace_airspace_id}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <Panel
            title={t("ansp.overview.inbox_title")}
            description={t("ansp.overview.inbox_description")}
            data-testid="overview-inbox"
            actions={
              <Button asChild variant="ghost" size="sm">
                <Link href={`/${lang}/inbox`}>{t("ansp.status.open_inbox")}</Link>
              </Button>
            }
          >
            {inbox.failure !== null && <ProblemNotice failure={inbox.failure} />}
            {!inbox.loaded && inbox.failure === null && <Loading />}
            {inbox.loaded && awaitingNotices.length === 0 && <Empty textKey="ansp.overview.inbox_none" testId="overview-inbox-none" />}
            {awaitingNotices.length > 0 && (
              <ul className="m-0 flex list-none flex-col p-0">
                {awaitingNotices.slice(0, PANEL_ROWS).map((n) => {
                  const loud = groupOf(n) === "escalated";
                  return (
                    <li
                      key={n.ack_id}
                      className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-border py-2.5 text-sm last:border-b-0"
                      data-ack={n.ack_id}
                      data-group={groupOf(n)}
                    >
                      <span className="flex min-w-0 flex-col">
                        <span className="font-semibold">{t(`ansp.inbox.kind.${n.kind}`)}</span>
                        <span className="text-xs text-muted-foreground">
                          {n.ussp_id} · <Time iso={n.received_at} />
                        </span>
                      </span>
                      <StatusBadge tone={loud ? "critical" : "warning"}>{t(`ansp.inbox.state.${n.state}`)}</StatusBadge>
                    </li>
                  );
                })}
              </ul>
            )}
            {awaitingNotices.length > PANEL_ROWS && (
              <p className="m-0 pt-2 text-xs text-muted-foreground">{t("ansp.overview.more", { count: awaitingNotices.length - PANEL_ROWS })}</p>
            )}
          </Panel>
        </div>

        <Panel
          title={t("ansp.overview.sources_title")}
          description={t("ansp.overview.sources_description")}
          data-testid="overview-sources"
          actions={
            <Button asChild variant="ghost" size="sm">
              <Link href={`/${lang}/adapters`}>{t("ansp.overview.view_all")}</Link>
            </Button>
          }
          footer={
            <dl className="m-0 grid gap-2 text-xs">
              <div className="grid gap-1">
                <dt className="font-semibold text-muted-foreground">{t("ansp.overview.stream.restrictions")}</dt>
                <dd className="m-0">
                  <FeedStatusBar status={feed} nowMs={nowMs} />
                </dd>
              </div>
              <div className="grid gap-1">
                <dt className="font-semibold text-muted-foreground">{t("ansp.overview.stream.coordination")}</dt>
                <dd className="m-0">
                  <FeedStatusBar status={inbox.feed} nowMs={nowMs} />
                </dd>
              </div>
            </dl>
          }
        >
          {adapters.failure !== null && <ProblemNotice failure={adapters.failure} />}
          {adapters.data === null && adapters.failure === null && <Loading />}
          {adapters.data !== null && adapters.data.length === 0 && <Empty textKey="ansp.adapters.none" testId="overview-adapters-none" />}
          {adapters.data !== null && adapters.data.length > 0 && (
            <ul className="m-0 flex list-none flex-col p-0">
              {adapters.data.map((a) => {
                const line = statusLine(a, switchFor(a, sources.data ?? []));
                return (
                  <li key={a.id} className="flex flex-col gap-1 border-b border-border py-2.5 text-sm last:border-b-0" data-adapter={a.id} data-status={a.status}>
                    <span className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-semibold">{a.display_name}</span>
                      <StatusBadge tone={ADAPTER_TONE[a.status]}>{t(`ansp.overview.adapter.${a.status}`)}</StatusBadge>
                    </span>
                    <span className="text-xs text-muted-foreground">{t(line.key, timesShown(line.vars, lang))}</span>
                  </li>
                );
              })}
            </ul>
          )}
          {sources.failure !== null && <ProblemNotice failure={sources.failure} />}
        </Panel>
      </div>
    </div>
  );
}
