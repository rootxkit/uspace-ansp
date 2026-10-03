"use client";

// /<locale>/restrictions: every restriction with its state, window,
// U-space airspace, version and delivery state per channel, and the
// open delivery alarms, live through the restriction stream; the map
// beside it draws them in the kit's symbology. An alarm stays on the page
// until the API clears it (CLAUDE.md rule 4); an empty list says why.
import Link from "next/link";
import { useMemo, useState } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { ConsoleMap } from "./ConsoleMap";
import { useConsole } from "./context";
import { toView } from "./adapt";
import { deliveryLines, openAlarmsOf, type ApiAlarm, type ApiRestriction } from "./delivery";
import { maySupervise } from "./roles";
import { Empty, Loading, ProblemNotice, ReasonAction, StateBadge, Time, timesShown } from "./ui";
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
          className={`list-none ${l.attention ? "font-semibold text-[var(--us-danger)]" : ""}`}
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
    <ul className="m-0 flex flex-col gap-2 p-0" data-testid="alarms">
      {open.map((a) => (
        <li key={a.id} role="alert" className="list-none rounded border border-[var(--us-danger)] p-2 text-sm" data-kind={a.kind} data-state={a.state}>
          <p className="m-0 font-semibold text-[var(--us-danger)]">
            {t(`ansp.alarm.kind.${a.kind}`)} · {t(`ansp.alarm.state.${a.state}`)}
          </p>
          <p className="m-0">{a.detail}</p>
          <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.alarm.since", timesShown({ since: a.since }, lang))}</p>
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
        </li>
      ))}
    </ul>
  );
}

export function RestrictionsPage() {
  const t = useT();
  const { lang } = useLang();
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("all");
  const live = useRestrictions(filter === "all" ? null : filter);
  const views = useMemo(() => (live.restrictions ?? []).map((r) => toView(r, lang)), [live.restrictions, lang]);
  const circles = (live.restrictions ?? []).filter((r) => r.geometry.type === "Point").length;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="m-0 text-lg font-semibold">{t("ansp.restrictions.title")}</h2>
        <Link href={`/${lang}/restrictions/new`} className="text-sm underline" data-testid="plan-link">
          {t("ansp.restrictions.plan")}
        </Link>
      </div>
      <p className="m-0 text-xs text-[var(--us-text-muted)]" data-testid="list-cis">
        {live.cisVersion === null
          ? t("ansp.restrictions.cis_none")
          : t("ansp.restrictions.cis", { version: live.cisVersion, age: live.cisAgeS === null ? "—" : Math.round(live.cisAgeS) })}
      </p>
      <section aria-label={t("ansp.alarms.label")} className="flex flex-col gap-2">
        <h3 className="m-0 text-base font-semibold">{t("ansp.alarms.title")}</h3>
        {live.alarmsFailure !== null && <ProblemNotice failure={live.alarmsFailure} />}
        <AlarmList alarms={live.alarms} onChanged={live.reload} />
      </section>
      <div className="flex flex-col gap-4 lg:flex-row">
        <div className="flex flex-1 flex-col gap-2">
          <label className="flex items-center gap-2 text-sm">
            {t("ansp.restrictions.filter")}
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value as (typeof FILTERS)[number])}
              className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1"
              data-testid="state-filter"
            >
              {FILTERS.map((f) => (
                <option key={f} value={f}>
                  {t(`ansp.restrictions.filter.${f}`)}
                </option>
              ))}
            </select>
          </label>
          {live.failure !== null && <ProblemNotice failure={live.failure} />}
          {live.restrictions === null && live.failure === null && <Loading />}
          {live.restrictions !== null && live.restrictions.length === 0 && (
            <Empty textKey={filter === "all" ? "ansp.restrictions.none" : "ansp.restrictions.none_in_state"} vars={{ state: t(`ansp.restrictions.filter.${filter}`) }} testId="restrictions-none" />
          )}
          {live.truncated && <p className="m-0 text-xs">{t("ansp.restrictions.truncated")}</p>}
          {live.restrictions !== null && live.restrictions.length > 0 && (
            <table className="w-full border-collapse text-sm" data-testid="restrictions-table">
              <thead>
                <tr className="border-b border-[var(--us-border)] text-start">
                  <th className="p-1 text-start">{t("ansp.restrictions.col.identifier")}</th>
                  <th className="p-1 text-start">{t("ansp.restrictions.col.state")}</th>
                  <th className="p-1 text-start">{t("ansp.restrictions.col.window")}</th>
                  <th className="p-1 text-start">{t("ansp.restrictions.col.airspace")}</th>
                  <th className="p-1 text-start">{t("ansp.restrictions.col.version")}</th>
                  <th className="p-1 text-start">{t("ansp.restrictions.col.delivery")}</th>
                </tr>
              </thead>
              <tbody>
                {live.restrictions.map((r) => {
                  const alarms = openAlarmsOf(r.id, live.alarms);
                  return (
                    <tr key={r.id} className="border-b border-[var(--us-border)] align-top" data-restriction={r.identifier} data-state={r.state}>
                      <td className="p-1">
                        <Link href={`/${lang}/restrictions/${r.id}`} className="font-mono underline">
                          {r.identifier}
                        </Link>
                      </td>
                      <td className="p-1">
                        <StateBadge state={r.state} />
                      </td>
                      <td className="p-1">
                        <Time iso={r.starts_at} /> – <Time iso={r.ends_at} />
                      </td>
                      <td className="p-1 font-mono">{r.uspace_airspace_id}</td>
                      <td className="p-1" data-testid="version">
                        {t("ansp.restrictions.version", { version: r.ansp_version })}
                      </td>
                      <td className="p-1">
                        <DeliveryLines restriction={r} alarms={alarms} />
                        {alarms.length > 0 && (
                          <p className="m-0 font-semibold text-[var(--us-danger)]">{t("ansp.restrictions.alarms_open", { count: alarms.length })}</p>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
        <div className="flex flex-col gap-1 lg:w-[40%]">
          <ConsoleMap restrictions={views} />
          {circles > 0 && <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.map.circle_centre_only", { count: circles })}</p>}
        </div>
      </div>
    </div>
  );
}
