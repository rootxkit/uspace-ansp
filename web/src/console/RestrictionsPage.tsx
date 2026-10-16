"use client";

// /<locale>/restrictions: every restriction with its state, window,
// U-space airspace, version and delivery state per channel, and the
// open delivery alarms, live through the restriction stream; the map
// beside it draws them in the kit's symbology. An alarm stays on the page
// until the API clears it (CLAUDE.md rule 4); an empty list says why.
import Link from "next/link";
import { useMemo, useState } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Button, cn, MapPanel, Panel, TABLE_NOWRAP } from "@rootxkit/uspace-ui/ui";
import { ConsoleMap } from "./ConsoleMap";
import { useConsole } from "./context";
import { toView, withOutline } from "./adapt";
import { circleAreaOf, circleKey, undrawnCircles, useCircleOutlines } from "./outline";
import { deliveryLines, openAlarmsOf, type ApiAlarm, type ApiRestriction } from "./delivery";
import { maySupervise } from "./roles";
import { ConsolePageHeader, Empty, Loading, ProblemNotice, ReasonAction, Section, StateBadge, Time, timesShown } from "./ui";
import { useRestrictions } from "./useRestrictions";

const FILTERS = ["all", "planned", "active", "ended", "cancelled"] as const;

/** The delivery lines of a restriction, in words. */
export function DeliveryLines({ restriction, alarms }: { restriction: ApiRestriction; alarms: readonly ApiAlarm[] }) {
  const t = useT();
  const { lang } = useLang();
  return (
    <ul className="m-0 flex flex-col gap-0.5 p-0" data-testid="delivery-lines">
      {deliveryLines(restriction, alarms).map((l) => (
        <li
          key={l.key}
          className={`list-none ${l.attention ? "font-semibold text-status-critical" : ""}`}
          data-key={l.key}
          data-attention={l.attention}
        >
          {t(l.key, timesShown(l.vars, lang))}
        </li>
      ))}
    </ul>
  );
}

/** The open alarms, each with its acknowledgement (a watch supervisor's act, with a reason). */
export function AlarmList({ alarms, onChanged }: { alarms: readonly ApiAlarm[]; onChanged(): void }) {
  const t = useT();
  const { lang } = useLang();
  const { client, role } = useConsole();
  const open = alarms.filter((a) => a.state !== "cleared");
  if (open.length === 0) return <Empty textKey="ansp.alarms.none" testId="alarms-none" />;
  return (
    <div className="flex flex-col gap-2" data-testid="alarms">
      {open.map((a) => (
        <div
          key={a.id}
          role="alert"
          className="flex flex-col gap-1 rounded-lg border border-status-critical-border bg-status-critical-soft p-3 text-sm"
          data-kind={a.kind}
          data-state={a.state}
        >
          <p className="m-0 font-semibold text-status-critical">
            {t(`ansp.alarm.kind.${a.kind}`)} · {t(`ansp.alarm.state.${a.state}`)}
          </p>
          <p className="m-0">{a.detail}</p>
          <p className="m-0 text-xs text-muted-foreground">{t("ansp.alarm.since", timesShown({ since: a.since }, lang))}</p>
          {a.state === "open" && maySupervise(role) && (
            <ReasonAction
              labelKey="ansp.alarm.acknowledge"
              titleKey="ansp.alarm.acknowledge_title"
              bodyKey={a.kind === "cisp_not_published" || a.kind === "uss_notify_late" ? "ansp.alarm.acknowledge_body_stays" : "ansp.alarm.acknowledge_body"}
              doneKey="ansp.alarm.acknowledged"
              act={(reason) => client.POST("/v1/delivery-alarms/{id}/acknowledge", { params: { path: { id: a.id } }, body: { reason } })}
              onDone={onChanged}
              testId={`acknowledge-${a.id}`}
            />
          )}
        </div>
      ))}
    </div>
  );
}

export function RestrictionsPage() {
  const t = useT();
  const { lang } = useLang();
  const { client } = useConsole();
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("all");
  const live = useRestrictions(filter === "all" ? null : filter);
  const circles = useMemo(() => (live.restrictions ?? []).flatMap((r) => circleAreaOf(r) ?? []), [live.restrictions]);
  const outlines = useCircleOutlines(client, circles);
  const views = useMemo(
    () =>
      (live.restrictions ?? []).map((r) => {
        const c = circleAreaOf(r);
        return withOutline(toView(r, lang), c === null ? undefined : outlines.get(circleKey(c)));
      }),
    [live.restrictions, lang, outlines],
  );
  const undrawn = undrawnCircles(circles, outlines);

  return (
    <div className="flex flex-col gap-6">
      <ConsolePageHeader
        titleKey="ansp.restrictions.title"
        descriptionKey="ansp.restrictions.description"
        meta={
          <span className="text-xs text-muted-foreground" data-testid="list-cis">
            {live.cisVersion === null
              ? t("ansp.restrictions.cis_none")
              : t("ansp.restrictions.cis", { version: live.cisVersion, age: live.cisAgeS === null ? "—" : Math.round(live.cisAgeS) })}
          </span>
        }
        actions={
          <Button asChild size="sm">
            <Link href={`/${lang}/restrictions/new`} data-testid="plan-link">
              {t("ansp.restrictions.plan")}
            </Link>
          </Button>
        }
      />
      <Section titleKey="ansp.alarms.title">
        {live.alarmsFailure !== null && <ProblemNotice failure={live.alarmsFailure} />}
        <AlarmList alarms={live.alarms} onChanged={live.reload} />
      </Section>
      <div className="grid items-start gap-6 2xl:grid-cols-[minmax(0,1fr)_34rem]">
        <Panel
          title={t("ansp.restrictions.list_title")}
          bodyClassName="flex flex-col gap-3"
          actions={
            <label className="flex items-center gap-2 text-sm">
              {t("ansp.restrictions.filter")}
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value as (typeof FILTERS)[number])}
                className="h-8 rounded-md border border-border bg-card px-2 text-sm"
                data-testid="state-filter"
              >
                {FILTERS.map((f) => (
                  <option key={f} value={f}>
                    {t(`ansp.restrictions.filter.${f}`)}
                  </option>
                ))}
              </select>
            </label>
          }
        >
          {live.failure !== null && <ProblemNotice failure={live.failure} />}
          {live.restrictions === null && live.failure === null && <Loading />}
          {live.restrictions !== null && live.restrictions.length === 0 && (
            <Empty textKey={filter === "all" ? "ansp.restrictions.none" : "ansp.restrictions.none_in_state"} vars={{ state: t(`ansp.restrictions.filter.${filter}`) }} testId="restrictions-none" />
          )}
          {live.truncated && <p className="m-0 text-xs">{t("ansp.restrictions.truncated")}</p>}
          {live.restrictions !== null && live.restrictions.length > 0 && (
            <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full border-collapse text-sm" data-testid="restrictions-table">
              <thead>
                <tr className="border-b border-border bg-panel-header text-start text-xs text-muted-foreground">
                  <th className="px-4 py-2 text-start font-semibold">{t("ansp.restrictions.col.identifier")}</th>
                  <th className="px-4 py-2 text-start font-semibold">{t("ansp.restrictions.col.state")}</th>
                  <th className="px-4 py-2 text-start font-semibold">{t("ansp.restrictions.col.window")}</th>
                  <th className="px-4 py-2 text-start font-semibold">{t("ansp.restrictions.col.airspace")}</th>
                  <th className="px-4 py-2 text-start font-semibold">{t("ansp.restrictions.col.version")}</th>
                  <th className="min-w-[18rem] px-4 py-2 text-start font-semibold">{t("ansp.restrictions.col.delivery")}</th>
                </tr>
              </thead>
              <tbody>
                {live.restrictions.map((r) => {
                  const alarms = openAlarmsOf(r.id, live.alarms);
                  return (
                    <tr key={r.id} className="border-b border-border align-top last:border-b-0 hover:bg-hover" data-restriction={r.identifier} data-state={r.state}>
                      <td className={cn("px-4 py-2.5", TABLE_NOWRAP)}>
                        <Link href={`/${lang}/restrictions/${r.id}`} className="font-mono font-semibold underline underline-offset-2">
                          {r.identifier}
                        </Link>
                      </td>
                      <td className="px-4 py-2.5">
                        <StateBadge state={r.state} />
                      </td>
                      <td className="px-4 py-2.5">
                        <Time iso={r.starts_at} /> – <Time iso={r.ends_at} />
                      </td>
                      <td className={cn("px-4 py-2.5 font-mono", TABLE_NOWRAP)}>{r.uspace_airspace_id}</td>
                      <td className={cn("px-4 py-2.5", TABLE_NOWRAP)} data-testid="version">
                        {t("ansp.restrictions.version", { version: r.ansp_version })}
                      </td>
                      <td className="px-4 py-2.5">
                        <DeliveryLines restriction={r} alarms={alarms} />
                        {alarms.length > 0 && (
                          <p className="m-0 font-semibold text-status-critical">{t("ansp.restrictions.alarms_open", { count: alarms.length })}</p>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            </div>
          )}
        </Panel>
        <MapPanel
          title={t("ansp.map.title")}
          mapClassName="h-[32rem]"
          {...(undrawn > 0 ? { footer: <p className="m-0 text-xs text-muted-foreground">{t("ansp.map.circle_centre_only", { count: undrawn })}</p> } : {})}
        >
          <ConsoleMap restrictions={views} fill />
        </MapPanel>
      </div>
    </div>
  );
}
