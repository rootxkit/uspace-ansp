"use client";

// /<locale>/occurrences/new: an occurrence report of ANSP staff (Reg.
// (EU) 376/2014 Art. 4(8); POST /v1/occurrences, x-auth
// session:watch_supervisor), queued by the API to the authority through
// its outbox. The form has the occurrence/v1 fields of 04 §3.3, the 72 h
// deadline after the reporter became aware, and, once queued, the API's
// receipt (report reference, state, deadline_at). The delivery state of
// one report has no read in the contract yet (docs/PLAN.md section 15
// row 52): the page lists the open occurrence_undelivered alarms of
// GET /v1/delivery-alarms, which the API raises 60 h after awareness for
// a report not yet delivered. The reporter reference is protected: it is
// sent once and never shown back. A send that got no answer is never
// repeated by itself (the operation takes no idempotency key).
import { useState } from "react";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Button, Input, Label, Textarea } from "@rootxkit/uspace-ui/ui";
import { failureOf, type CallFailure } from "../api/client";
import { useConsole, useLoad } from "./context";
import {
  CATEGORIES,
  CHANNELS,
  deadlinePreview,
  emptyForm,
  occurrenceBody,
  outcomeAfter,
  REPORTER_REF_MAX_CHARS,
  type ApiOccurrenceQueued,
  type FormProblem,
  type OccurrenceForm,
} from "./occurrence";
import { maySupervise } from "./roles";
import { Empty, ProblemNotice, Section, Time, timesShown } from "./ui";

function Problems({ problems, field }: { problems: FormProblem[]; field: string }) {
  const t = useT();
  const mine = problems.filter((p) => p.field === field || p.field.startsWith(`${field}[`) || p.field.startsWith(`${field}.`));
  if (mine.length === 0) return null;
  return (
    <ul className="m-0 ps-4 text-xs text-[var(--us-danger)]">
      {mine.map((p) => (
        <li key={`${p.field}-${p.problem}`}>
          <code>{p.field}</code>: {t(`ansp.occurrence.problem.${p.problem}`)}
        </li>
      ))}
    </ul>
  );
}

function UndeliveredAlarms() {
  const t = useT();
  const { lang } = useLang();
  const alarms = useLoad(async (c) => (await c.GET("/v1/delivery-alarms", { params: { query: { limit: 1000 } } })).data?.alarms ?? [], "occurrence-alarms");
  if (alarms.failure !== null) return <ProblemNotice failure={alarms.failure} />;
  if (alarms.data === null) return null;
  const open = alarms.data.filter((a) => a.kind === "occurrence_undelivered" && a.state !== "cleared");
  if (open.length === 0) return <Empty textKey="ansp.occurrence.undelivered_none" testId="occurrence-undelivered-none" />;
  return (
    <ul className="m-0 flex flex-col gap-1 p-0" data-testid="occurrence-undelivered">
      {open.map((a) => (
        <li key={a.id} role="alert" className="list-none rounded border border-[var(--us-danger)] p-2 text-sm">
          <p className="m-0 font-semibold text-[var(--us-danger)]">{t("ansp.occurrence.undelivered", timesShown({ since: a.since }, lang))}</p>
          <p className="m-0">{a.detail}</p>
        </li>
      ))}
    </ul>
  );
}

export function OccurrencePage() {
  const t = useT();
  const { lang } = useLang();
  const { client, role } = useConsole();
  const [form, setForm] = useState<OccurrenceForm>(emptyForm);
  const [typed, setTyped] = useState({ occurred_at: "", became_aware_at: "", min_at: "" });
  const [problems, setProblems] = useState<FormProblem[]>([]);
  const [failure, setFailure] = useState<CallFailure | null>(null);
  const [unknown, setUnknown] = useState(false);
  const [resendAnyway, setResendAnyway] = useState(false);
  const [busy, setBusy] = useState(false);
  const [queued, setQueued] = useState<ApiOccurrenceQueued | null>(null);

  if (!maySupervise(role)) return <Empty textKey="ansp.occurrence.role" testId="occurrence-role" />;

  const set = <K extends keyof OccurrenceForm>(k: K, v: OccurrenceForm[K]) => setForm((f) => ({ ...f, [k]: v }));
  const setTime = (k: "occurred_at" | "became_aware_at" | "min_at", v: string) => {
    setTyped((x) => ({ ...x, [k]: v }));
    set(k, v === "" ? null : inputToUtc(v));
  };
  const deadline = deadlinePreview(form.became_aware_at);

  const submit = async () => {
    setFailure(null);
    const built = occurrenceBody(form);
    if ("problems" in built) {
      setProblems(built.problems);
      return;
    }
    setProblems([]);
    setBusy(true);
    try {
      const { data } = await client.POST("/v1/occurrences", { body: built.body });
      if (data !== undefined) {
        setQueued(data);
        setForm(emptyForm());
        setTyped({ occurred_at: "", became_aware_at: "", min_at: "" });
        setUnknown(false);
        setResendAnyway(false);
      }
    } catch (err: unknown) {
      const f = failureOf(err);
      setFailure(f);
      setUnknown(outcomeAfter(f) === "unknown");
      setResendAnyway(false);
    } finally {
      setBusy(false);
    }
  };

  const timeField = (k: "occurred_at" | "became_aware_at" | "min_at", labelKey: string, required: boolean) => (
    <div className="flex flex-col gap-0.5">
      <Label htmlFor={`occ-${k}`}>{t(labelKey)}</Label>
      <Input
        id={`occ-${k}`}
        type="datetime-local"
        value={typed[k]}
        onChange={(e) => setTime(k, e.target.value)}
        required={required}
        data-testid={`occ-${k}`}
      />
      <Problems problems={problems} field={k} />
    </div>
  );

  return (
    <div className="flex max-w-4xl flex-col gap-4">
      <h2 className="m-0 text-lg font-semibold">{t("ansp.occurrence.title")}</h2>
      <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.occurrence.intro")}</p>
      {queued !== null && (
        <div role="status" className="rounded border border-[var(--us-border-strong)] p-3 text-sm" data-testid="occurrence-queued" data-state={queued.state}>
          <p className="m-0 font-semibold">{t("ansp.occurrence.queued", { ref: queued.report_ref })}</p>
          <p className="m-0">
            {t("ansp.occurrence.deadline_api")} <Time iso={queued.deadline_at} />
          </p>
          <p className="m-0 text-xs">{t("ansp.occurrence.delivery_unread")}</p>
        </div>
      )}
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (!unknown || resendAnyway) void submit();
        }}
      >
        <div className="grid gap-3 md:grid-cols-2">
          <div className="flex flex-col gap-0.5">
            <Label htmlFor="occ-channel">{t("ansp.occurrence.channel")}</Label>
            <select id="occ-channel" value={form.channel} onChange={(e) => set("channel", e.target.value)} className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1">
              {CHANNELS.map((c) => (
                <option key={c} value={c}>
                  {t(`ansp.occurrence.channel.${c}`)}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-0.5">
            <Label htmlFor="occ-category">{t("ansp.occurrence.category")}</Label>
            <select id="occ-category" value={form.category} onChange={(e) => set("category", e.target.value)} className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1">
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {t(`ansp.occurrence.category.${c}`)}
                </option>
              ))}
            </select>
          </div>
          {timeField("occurred_at", "ansp.occurrence.occurred_at", true)}
          {timeField("became_aware_at", "ansp.occurrence.became_aware_at", true)}
        </div>
        <p className="m-0 text-sm" data-testid="occurrence-deadline">
          {deadline === null ? t("ansp.occurrence.deadline_none") : t("ansp.occurrence.deadline", timesShown({ at: deadline }, lang))}
        </p>

        <fieldset className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-2">
          <legend className="px-1 text-sm font-semibold">{t("ansp.occurrence.aircraft")}</legend>
          {form.aircraft.map((a, i) => (
            <div key={i} className="grid gap-2 md:grid-cols-4" data-testid="occ-aircraft-row">
              {(["serial", "operator_reg", "flight_id", "authorisation_number"] as const).map((k) => (
                <div key={k} className="flex flex-col gap-0.5">
                  <Label htmlFor={`occ-aircraft-${i}-${k}`}>{t(`ansp.occurrence.aircraft.${k}`)}</Label>
                  <Input
                    id={`occ-aircraft-${i}-${k}`}
                    value={a[k]}
                    onChange={(e) => set("aircraft", form.aircraft.map((x, j) => (j === i ? { ...x, [k]: e.target.value } : x)))}
                  />
                </div>
              ))}
            </div>
          ))}
          <Problems problems={problems} field="aircraft" />
          <div>
            <Button type="button" size="sm" variant="outline" onClick={() => set("aircraft", [...form.aircraft, { serial: "", operator_reg: "", flight_id: "", authorisation_number: "" }])}>
              {t("ansp.occurrence.add_aircraft")}
            </Button>
          </div>
        </fieldset>

        <fieldset className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-2">
          <legend className="px-1 text-sm font-semibold">{t("ansp.occurrence.manned")}</legend>
          {form.manned.map((m, i) => (
            <div key={i} className="grid gap-2 md:grid-cols-2" data-testid="occ-manned-row">
              <div className="flex flex-col gap-0.5">
                <Label htmlFor={`occ-manned-${i}-icao24`}>{t("ansp.occurrence.manned.icao24")}</Label>
                <Input id={`occ-manned-${i}-icao24`} value={m.icao24} onChange={(e) => set("manned", form.manned.map((x, j) => (j === i ? { ...x, icao24: e.target.value } : x)))} className="font-mono" />
              </div>
              <div className="flex flex-col gap-0.5">
                <Label htmlFor={`occ-manned-${i}-callsign`}>{t("ansp.occurrence.manned.callsign")}</Label>
                <Input id={`occ-manned-${i}-callsign`} value={m.callsign} onChange={(e) => set("manned", form.manned.map((x, j) => (j === i ? { ...x, callsign: e.target.value } : x)))} />
              </div>
            </div>
          ))}
          <Problems problems={problems} field="manned" />
          <div>
            <Button type="button" size="sm" variant="outline" onClick={() => set("manned", [...form.manned, { icao24: "", callsign: "" }])}>
              {t("ansp.occurrence.add_manned")}
            </Button>
          </div>
        </fieldset>

        <div className="flex flex-col gap-0.5">
          <Label htmlFor="occ-intents">{t("ansp.occurrence.intent_refs")}</Label>
          <Textarea id="occ-intents" rows={2} value={form.intent_refs} onChange={(e) => set("intent_refs", e.target.value)} className="font-mono text-xs" />
          <Problems problems={problems} field="intent_refs" />
        </div>

        <fieldset className="grid gap-2 rounded border border-[var(--us-border)] p-2 md:grid-cols-3">
          <legend className="px-1 text-sm font-semibold">{t("ansp.occurrence.min_separation")}</legend>
          <div className="flex flex-col gap-0.5">
            <Label htmlFor="occ-min-h">{t("ansp.occurrence.min_h_m")}</Label>
            <Input id="occ-min-h" inputMode="decimal" value={form.min_h_m} onChange={(e) => set("min_h_m", e.target.value)} />
          </div>
          <div className="flex flex-col gap-0.5">
            <Label htmlFor="occ-min-v">{t("ansp.occurrence.min_v_m")}</Label>
            <Input id="occ-min-v" inputMode="decimal" value={form.min_v_m} onChange={(e) => set("min_v_m", e.target.value)} />
          </div>
          {timeField("min_at", "ansp.occurrence.min_at", false)}
          <div className="md:col-span-3">
            <Problems problems={problems} field="min_separation" />
          </div>
        </fieldset>

        <div className="flex flex-col gap-0.5">
          <Label htmlFor="occ-narrative">{t("ansp.occurrence.narrative")}</Label>
          <Textarea id="occ-narrative" rows={5} value={form.narrative} onChange={(e) => set("narrative", e.target.value)} data-testid="occ-narrative" />
          <Problems problems={problems} field="narrative" />
        </div>

        <div className="flex flex-col gap-0.5 rounded border border-dashed border-[var(--us-danger)] p-2" data-testid="occ-reporter">
          <Label htmlFor="occ-reporter">
            {t("ansp.occurrence.reporter")}{" "}
            <span className="rounded border border-[var(--us-danger)] px-1 text-xs font-semibold text-[var(--us-danger)]" data-testid="occ-reporter-protected">
              {t("ansp.occurrence.protected")}
            </span>
          </Label>
          <Input
            id="occ-reporter"
            value={form.reporter_person_ref}
            onChange={(e) => set("reporter_person_ref", e.target.value)}
            autoComplete="off"
            spellCheck={false}
            maxLength={REPORTER_REF_MAX_CHARS}
          />
          <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.occurrence.reporter_hint")}</p>
          <Problems problems={problems} field="reporter_person_ref" />
        </div>

        {unknown && (
          <div role="alert" className="flex flex-col gap-1 rounded border border-[var(--us-danger)] p-2 text-sm" data-testid="occurrence-unknown">
            <p className="m-0 font-semibold">{t("ansp.occurrence.unknown")}</p>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={resendAnyway} onChange={(e) => setResendAnyway(e.target.checked)} data-testid="occ-resend" />
              {t("ansp.occurrence.resend_anyway")}
            </label>
          </div>
        )}
        <div>
          <Button type="submit" disabled={busy || (unknown && !resendAnyway)} data-testid="occ-submit">
            {t("ansp.occurrence.submit")}
          </Button>
        </div>
        {failure !== null && <ProblemNotice failure={failure} />}
      </form>
      <Section titleKey="ansp.occurrence.delivery">
        <UndeliveredAlarms />
      </Section>
    </div>
  );
}
