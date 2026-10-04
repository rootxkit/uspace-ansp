"use client";

// /<locale>/restrictions/<id>: one restriction, live: its state, window,
// limits and who did what when; the delivery state per channel; the
// F3548 constraint reference; the ED-318 feature as published; every
// version (the N4 record); the alarms raised for it, cleared ones
// included. The acts a watch supervisor has here (activate, extend, end,
// cancel) each go through a confirmation that says what will be sent to
// whom, with a reason the API records (audited, ATS.TR.237(b)).
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Input, Label } from "@rootxkit/uspace-ui/ui";
import { toView } from "./adapt";
import { ConsoleMap } from "./ConsoleMap";
import { useConsole, useLoad } from "./context";
import type { ApiAlarm, ApiRestriction } from "./delivery";
import { mergeAlarm, mergeState, stateBodyOf, type ApiStateBody } from "./restrictions";
import { AlarmList, DeliveryLines } from "./RestrictionsPage";
import { maySupervise } from "./roles";
import { Loading, ProblemNotice, ReasonAction, Section, StateBadge, Time, utcText } from "./ui";

/** The frames of one restriction the page keeps. Display-only bound. */
const FRAMES_KEPT = 50;

function Row({ labelKey, children }: { labelKey: string; children: React.ReactNode }) {
  const t = useT();
  return (
    <>
      <dt className="font-semibold">{t(labelKey)}</dt>
      <dd className="m-0">{children}</dd>
    </>
  );
}

function Json({ value, testId }: { value: unknown; testId: string }) {
  return (
    <pre data-testid={testId} className="m-0 max-h-80 overflow-auto rounded border border-[var(--us-border)] bg-[var(--us-surface-sunken)] p-2 text-xs">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

/** The acts open to a watch supervisor in this state, each confirmed with a reason. */
function Acts({ r, onDone }: { r: ApiRestriction; onDone(): void }) {
  const t = useT();
  const { lang } = useLang();
  const { client, role } = useConsole();
  const [endsLocal, setEndsLocal] = useState("");
  if (!maySupervise(role)) return <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.detail.acts_role")}</p>;
  const vars = {
    identifier: r.identifier,
    version: r.ansp_version,
    starts: utcText(r.starts_at, lang),
    ends: utcText(r.ends_at, lang),
    airspace: r.uspace_airspace_id ?? "—",
  };
  const newEnds = inputToUtc(endsLocal);
  const path = { params: { path: { id: r.id } } };
  return (
    <div className="flex flex-wrap items-start gap-4" data-testid="acts">
      {r.state === "planned" && (
        <ReasonAction
          labelKey="ansp.act.activate"
          titleKey="ansp.act.activate_title"
          bodyKey="ansp.act.activate_body"
          vars={vars}
          doneKey="ansp.act.activate_done"
          act={(reason) => client.POST("/v1/restrictions/{id}/activate", { ...path, body: { reason } })}
          onDone={onDone}
          testId="act-activate"
        />
      )}
      {(r.state === "planned" || r.state === "active") && (
        <div className="flex flex-col gap-1">
          <Label htmlFor="extend-ends">{t("ansp.act.extend_ends")}</Label>
          <Input id="extend-ends" type="datetime-local" value={endsLocal} onChange={(e) => setEndsLocal(e.target.value)} data-testid="extend-ends" />
          <ReasonAction
            labelKey="ansp.act.extend"
            titleKey="ansp.act.extend_title"
            bodyKey="ansp.act.extend_body"
            vars={{ ...vars, new_ends: newEnds === null ? "—" : utcText(newEnds, lang) }}
            doneKey="ansp.act.extend_done"
            disabled={newEnds === null}
            act={(reason) => client.POST("/v1/restrictions/{id}/extend", { ...path, body: { ends_at: newEnds ?? "", reason } })}
            onDone={onDone}
            testId="act-extend"
          />
        </div>
      )}
      {r.state === "active" && (
        <ReasonAction
          labelKey="ansp.act.end"
          titleKey="ansp.act.end_title"
          bodyKey="ansp.act.end_body"
          vars={vars}
          destructive
          doneKey="ansp.act.end_done"
          act={(reason) => client.POST("/v1/restrictions/{id}/end", { ...path, body: { reason } })}
          onDone={onDone}
          testId="act-end"
        />
      )}
      {r.state === "planned" && (
        <ReasonAction
          labelKey="ansp.act.cancel"
          titleKey="ansp.act.cancel_title"
          bodyKey="ansp.act.cancel_body"
          vars={vars}
          destructive
          doneKey="ansp.act.cancel_done"
          act={(reason) => client.POST("/v1/restrictions/{id}/cancel", { ...path, body: { reason } })}
          onDone={onDone}
          testId="act-cancel"
        />
      )}
    </div>
  );
}

export function RestrictionDetailPage({ id }: { id: string }) {
  const t = useT();
  const { lang } = useLang();
  const { onFrame } = useConsole();
  const loaded = useLoad(async (c) => (await c.GET("/v1/restrictions/{id}", { params: { path: { id } } })).data ?? null, `r:${id}`);
  const versions = useLoad(
    async (c) => (await c.GET("/v1/restrictions/{id}/versions", { params: { path: { id } } })).data?.versions ?? [],
    `v:${id}`,
  );
  const alarmsLoad = useLoad(async (c) => (await c.GET("/v1/delivery-alarms", { params: { query: { all: true, limit: 500 } } })).data?.alarms ?? [], `a:${id}`);
  // The frames of this restriction since the page opened, newest last
  // (bounded: a frame older than the REST answer is ignored by version).
  const [bodies, setBodies] = useState<ApiStateBody[]>([]);
  const { reload: reloadVersions } = versions;
  useEffect(
    () =>
      onFrame((frame) => {
        const body = stateBodyOf(frame);
        if (body === null || body.restriction_id !== id) return;
        setBodies((prev) => [...prev, body].slice(-FRAMES_KEPT));
        reloadVersions();
      }),
    [onFrame, id, reloadVersions],
  );

  // The REST answers, then the frames on top.
  const live = useMemo(() => {
    let r: ApiRestriction | null = loaded.data;
    let alarms: ApiAlarm[] = (alarmsLoad.data ?? []).filter((a) => a.restriction_id === id);
    for (const b of bodies) {
      if (r !== null) r = mergeState([r], b).restrictions[0] ?? r;
      alarms = mergeAlarm(alarms, b.alarm);
    }
    return { r, alarms };
  }, [loaded.data, alarmsLoad.data, bodies, id]);

  const r = live.r;
  const views = useMemo(() => (r === null ? [] : [toView(r, lang)]), [r, lang]);
  const reloadAll = () => {
    loaded.reload();
    versions.reload();
    alarmsLoad.reload();
  };

  if (loaded.failure !== null && r === null) return <ProblemNotice failure={loaded.failure} />;
  if (r === null) return <Loading />;
  const open = live.alarms.filter((a) => a.state !== "cleared");

  return (
    <div className="flex flex-col gap-4" data-testid="restriction-detail" data-state={r.state}>
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="m-0 font-mono text-lg font-semibold">{r.identifier}</h2>
        <StateBadge state={r.state} />
        <span data-testid="version">{t("ansp.restrictions.version", { version: r.ansp_version })}</span>
        <Link href={`/${lang}/restrictions`} className="text-sm underline">
          {t("ansp.detail.back")}
        </Link>
      </div>
      {loaded.failure !== null && <ProblemNotice failure={loaded.failure} />}
      <Acts r={r} onDone={reloadAll} />
      <div className="flex flex-col gap-4 lg:flex-row">
        <div className="flex flex-1 flex-col gap-4">
          <Section titleKey="ansp.detail.summary">
            <dl className="m-0 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
              <Row labelKey="ansp.detail.window">
                <Time iso={r.starts_at} /> – <Time iso={r.ends_at} />
              </Row>
              {r.activate_at !== undefined && r.activate_at !== null && (
                <Row labelKey="ansp.detail.activate_at">
                  <Time iso={r.activate_at} />
                </Row>
              )}
              <Row labelKey="ansp.detail.airspace">
                <code>{r.uspace_airspace_id}</code>
              </Row>
              <Row labelKey="ansp.detail.zone_type">{t(`ansp.zone_type.${r.zone_type}`)}</Row>
              <Row labelKey="ansp.detail.limits">
                {t("ansp.detail.limits_value", { lower: r.lower_m, lower_ref: r.lower_ref, upper: r.upper_m, upper_ref: r.upper_ref })}
              </Row>
              <Row labelKey="ansp.detail.area">
                {r.geometry.type === "Point" ? t("ansp.detail.area_circle", { radius: r.radius_m ?? "—" }) : t("ansp.detail.area_polygon")}
              </Row>
              <Row labelKey="ansp.detail.reason">{r.reason_text}</Row>
              <Row labelKey="ansp.detail.created">
                {t(`ansp.changed_by.${r.created_by}`)} · <Time iso={r.created_at} />
              </Row>
              {r.activated_by !== undefined && (
                <Row labelKey="ansp.detail.activated">
                  {t(`ansp.changed_by.${r.activated_by}`)} · <Time iso={r.activated_at} />
                </Row>
              )}
              {r.ended_by !== undefined && (
                <Row labelKey="ansp.detail.ended">
                  {t(`ansp.changed_by.${r.ended_by}`)} · <Time iso={r.ended_at_actual} />
                </Row>
              )}
              {r.cancelled_by !== undefined && <Row labelKey="ansp.detail.cancelled">{t(`ansp.changed_by.${r.cancelled_by}`)}</Row>}
              {r.supersedes_id !== undefined && r.supersedes_id !== null && (
                <Row labelKey="ansp.detail.supersedes">
                  <Link href={`/${lang}/restrictions/${r.supersedes_id}`} className="font-mono underline">
                    {r.supersedes_id}
                  </Link>
                </Row>
              )}
              {r.request_id !== undefined && r.request_id !== null && (
                <Row labelKey="ansp.detail.request">
                  <code>{r.request_id}</code>
                </Row>
              )}
              <Row labelKey="ansp.detail.ansp_ref">
                <code>{r.ansp_ref}</code>
              </Row>
              <Row labelKey="ansp.detail.cis">
                {r.cis_version === null
                  ? t("ansp.restrictions.cis_none")
                  : t("ansp.restrictions.cis", { version: r.cis_version, age: r.cis_age_s === null ? "—" : Math.round(r.cis_age_s) })}
              </Row>
            </dl>
          </Section>
          <Section titleKey="ansp.detail.deliveries">
            <DeliveryLines restriction={r} alarms={open} />
          </Section>
          <Section titleKey="ansp.detail.events">
            <AlarmList alarms={open} onChanged={reloadAll} />
            {live.alarms.filter((a) => a.state === "cleared").length > 0 && (
              <ul className="m-0 flex flex-col gap-1 p-0 text-xs" data-testid="alarms-cleared">
                {live.alarms
                  .filter((a) => a.state === "cleared")
                  .map((a) => (
                    <li key={a.id} className="list-none">
                      {t("ansp.alarm.cleared_line", {
                        kind: t(`ansp.alarm.kind.${a.kind}`),
                        since: utcText(a.since, lang),
                        cleared: utcText(a.cleared_at, lang),
                        reason: a.clear_reason ?? "—",
                      })}
                    </li>
                  ))}
              </ul>
            )}
          </Section>
        </div>
        <div className="flex flex-col gap-1 lg:w-[40%]">
          <ConsoleMap restrictions={views} />
          {r.geometry.type === "Point" && <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.map.circle_centre_only", { count: 1 })}</p>}
        </div>
      </div>
      <Section titleKey="ansp.detail.versions">
        {versions.failure !== null && <ProblemNotice failure={versions.failure} />}
        {versions.data === null ? (
          <Loading />
        ) : (
          <table className="w-full border-collapse text-sm" data-testid="versions">
            <thead>
              <tr className="border-b border-[var(--us-border)]">
                <th className="p-1 text-start">{t("ansp.detail.version.version")}</th>
                <th className="p-1 text-start">{t("ansp.detail.version.state")}</th>
                <th className="p-1 text-start">{t("ansp.detail.version.by")}</th>
                <th className="p-1 text-start">{t("ansp.detail.version.at")}</th>
                <th className="p-1 text-start">{t("ansp.detail.version.reason")}</th>
              </tr>
            </thead>
            <tbody>
              {versions.data.map((v) => (
                <tr key={v.version} className="border-b border-[var(--us-border)]">
                  <td className="p-1">{v.version}</td>
                  <td className="p-1">
                    <StateBadge state={v.state} />
                  </td>
                  <td className="p-1">{t(`ansp.changed_by.${v.changed_by}`)}</td>
                  <td className="p-1">
                    <Time iso={v.changed_at} />
                  </td>
                  <td className="p-1">{v.change_reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
      <Section titleKey="ansp.detail.reference">
        <p className="m-0 text-sm">
          {t("ansp.detail.reference_id")} <code>{r.dss_constraint_id}</code>
        </p>
        {r.constraint_reference === undefined || r.constraint_reference === null ? (
          <p className="m-0 text-sm" data-testid="f3548-none">
            {t("ansp.detail.reference_none")}
          </p>
        ) : (
          <Json value={r.constraint_reference} testId="f3548" />
        )}
      </Section>
      <Section titleKey="ansp.detail.feature">
        <Json value={r.feature} testId="feature" />
      </Section>
    </div>
  );
}
