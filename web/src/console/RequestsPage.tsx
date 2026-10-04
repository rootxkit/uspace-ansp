"use client";

// /<locale>/requests: restriction requests (02 F11) from the authority or
// a console user. api/openapi.yaml has no list of requests (GET
// /v1/restriction-requests/{id} only; docs/PLAN.md section 15 row 45), so
// a request is opened by its id, which the requester gives with it. The
// request is shown as the editor would hold it, pre-filled and drawn on
// the map: its area, limits, window and reason as asked. Accepting plans
// exactly that restriction (the API's accept takes the zone type and a
// reason, nothing else); declining sends the reason the requester reads.
// Both are a watch supervisor's acts, confirmed and audited.
import Link from "next/link";
import { useMemo, useState, type FormEvent } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Button, Input, Label } from "@rootxkit/uspace-ui/ui";
import { requestView } from "./adapt";
import { ConsoleMap } from "./ConsoleMap";
import { useConsole, useLoad } from "./context";
import { maySupervise } from "./roles";
import { Empty, Loading, ProblemNotice, ReasonAction, Section, Time, utcText } from "./ui";
import { ZONE_TYPES } from "./plan";

/** A request id as api/openapi.yaml takes it (a ULID). Shape only. */
export const REQUEST_ID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

function RequestView({ id }: { id: string }) {
  const t = useT();
  const { lang } = useLang();
  const { client, role } = useConsole();
  const [zoneType, setZoneType] = useState<(typeof ZONE_TYPES)[number]>("PROHIBITED");
  const req = useLoad(async (c) => (await c.GET("/v1/restriction-requests/{id}", { params: { path: { id } } })).data ?? null, `q:${id}`);
  const q = req.data;
  const views = useMemo(() => (q === null ? [] : [requestView(q.id, q.payload)]), [q]);
  if (req.failure !== null && q === null) return <ProblemNotice failure={req.failure} />;
  if (q === null) return <Loading />;
  const p = q.payload;
  const vars = {
    id: q.id,
    requester: q.requester,
    airspace: p.uspace_airspace_id ?? "—",
    starts: utcText(p.starts_at, lang),
    ends: utcText(p.ends_at, lang),
    zone_type: t(`ansp.zone_type.${zoneType}`),
  };
  return (
    <div className="flex flex-col gap-4 lg:flex-row" data-testid="request" data-state={q.state}>
      <div className="flex flex-1 flex-col gap-3">
        <Section titleKey="ansp.requests.request" vars={{ id: q.id }}>
          <dl className="m-0 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="font-semibold">{t("ansp.requests.state")}</dt>
            <dd className="m-0">{t(`ansp.requests.state.${q.state}`)}</dd>
            <dt className="font-semibold">{t("ansp.requests.from")}</dt>
            <dd className="m-0">{t(`ansp.requests.source.${q.source}`, { requester: q.requester })}</dd>
            <dt className="font-semibold">{t("ansp.requests.received")}</dt>
            <dd className="m-0">
              <Time iso={q.received_at} />
            </dd>
            <dt className="font-semibold">{t("ansp.detail.window")}</dt>
            <dd className="m-0">
              <Time iso={p.starts_at} /> – <Time iso={p.ends_at} />
            </dd>
            <dt className="font-semibold">{t("ansp.detail.airspace")}</dt>
            <dd className="m-0">
              <code>{p.uspace_airspace_id ?? "—"}</code>
            </dd>
            <dt className="font-semibold">{t("ansp.detail.limits")}</dt>
            <dd className="m-0">
              {t("ansp.detail.limits_value", { lower: p.lower_m, lower_ref: p.lower_ref, upper: p.upper_m, upper_ref: p.upper_ref })}
            </dd>
            <dt className="font-semibold">{t("ansp.detail.area")}</dt>
            <dd className="m-0">{p.geometry.type === "Point" ? t("ansp.detail.area_circle", { radius: p.radius_m ?? "—" }) : t("ansp.detail.area_polygon")}</dd>
            <dt className="font-semibold">{t("ansp.detail.reason")}</dt>
            <dd className="m-0">{p.reason_text}</dd>
            {p.case_ref !== undefined && (
              <>
                <dt className="font-semibold">{t("ansp.requests.case_ref")}</dt>
                <dd className="m-0">{p.case_ref}</dd>
              </>
            )}
            {q.decision_reason !== undefined && (
              <>
                <dt className="font-semibold">{t("ansp.requests.decision")}</dt>
                <dd className="m-0">{q.decision_reason}</dd>
              </>
            )}
          </dl>
        </Section>
        {q.state === "accepted" && q.restriction_id !== undefined && (
          <Link href={`/${lang}/restrictions/${q.restriction_id}`} className="underline" data-testid="request-restriction">
            {t("ansp.requests.open_restriction", { id: q.restriction_id })}
          </Link>
        )}
        {q.state === "received" && maySupervise(role) && (
          <div className="flex flex-wrap items-start gap-4" data-testid="request-acts">
            <div className="flex flex-col gap-1">
              <Label htmlFor="accept-zone-type">{t("ansp.field.zone_type")}</Label>
              <select
                id="accept-zone-type"
                value={zoneType}
                onChange={(e) => setZoneType(e.target.value as (typeof ZONE_TYPES)[number])}
                className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1 text-sm"
              >
                {ZONE_TYPES.map((z) => (
                  <option key={z} value={z}>
                    {t(`ansp.zone_type.${z}`)}
                  </option>
                ))}
              </select>
              <ReasonAction
                labelKey="ansp.requests.accept"
                titleKey="ansp.requests.accept_title"
                bodyKey="ansp.requests.accept_body"
                vars={vars}
                doneKey="ansp.requests.accepted"
                act={(reason) => client.POST("/v1/restriction-requests/{id}/accept", { params: { path: { id } }, body: { zone_type: zoneType, reason } })}
                onDone={req.reload}
                testId="request-accept"
              />
            </div>
            <ReasonAction
              labelKey="ansp.requests.decline"
              titleKey="ansp.requests.decline_title"
              bodyKey="ansp.requests.decline_body"
              vars={vars}
              destructive
              doneKey="ansp.requests.declined"
              act={(reason) => client.POST("/v1/restriction-requests/{id}/decline", { params: { path: { id } }, body: { reason } })}
              onDone={req.reload}
              testId="request-decline"
            />
          </div>
        )}
      </div>
      <div className="flex flex-col gap-1 lg:w-[45%]">
        <ConsoleMap restrictions={views} />
        {p.geometry.type === "Point" && <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.map.circle_centre_only", { count: 1 })}</p>}
      </div>
    </div>
  );
}

export function RequestsPage() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const params = useSearchParams();
  const id = params.get("id");
  const [typed, setTyped] = useState(id ?? "");
  const valid = REQUEST_ID.test(typed.trim());
  const open = (e: FormEvent) => {
    e.preventDefault();
    if (valid) router.push(`/${lang}/requests?id=${encodeURIComponent(typed.trim())}`);
  };
  return (
    <div className="flex flex-col gap-4">
      <h2 className="m-0 text-lg font-semibold">{t("ansp.requests.title")}</h2>
      <Empty textKey="ansp.requests.no_list" testId="requests-no-list" />
      <form onSubmit={open} className="flex flex-wrap items-end gap-2">
        <div className="flex flex-col gap-1">
          <Label htmlFor="request-id">{t("ansp.requests.id")}</Label>
          <Input id="request-id" value={typed} onChange={(e) => setTyped(e.target.value)} className="font-mono" data-testid="request-id" />
        </div>
        <Button type="submit" disabled={!valid} data-testid="request-open">
          {t("ansp.requests.open")}
        </Button>
      </form>
      {id !== null && REQUEST_ID.test(id) && <RequestView key={id} id={id} />}
    </div>
  );
}
