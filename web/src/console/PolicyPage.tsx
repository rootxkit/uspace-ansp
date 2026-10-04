"use client";

// /<locale>/policy: the thresholds row (INV-03), an administrator's
// (GET and PUT /v1/policy are x-auth session:admin). The row with its
// units as the names state them, its policy_version, who changed it and
// when; a change is confirmed with the thresholds it moves spelled out
// and writes the next policy_version (a version is never edited). The
// contract carries no reason for a change (PolicyUpdate has none,
// docs/PLAN.md section 15 row 52): the audit records who and when, and
// the page says so rather than ask for a reason it would throw away. The
// history is read from the audit log, one entry per version
// (ansp_policy:<version>). A refusal of the API, a 403 or a 501 for an
// operation it does not serve yet included, is shown as it said it.
import { useState } from "react";
import { ConfirmDialog } from "@rootxkit/uspace-ui/form";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Button, Input, Label } from "@rootxkit/uspace-ui/ui";
import { failureOf, type CallFailure } from "../api/client";
import type { ApiAuditEvent } from "./audit";
import { useConsole, useLoad } from "./context";
import { changes, formOf, historyVersions, policyAuditEntity, policyBody, THRESHOLDS, unitOf, ZONE_TYPES, type ApiPolicy, type ApiPolicyUpdate, type FormProblem, type PolicyForm } from "./policy";
import { mayAdminister } from "./roles";
import { Empty, Loading, ProblemNotice, Section, Time } from "./ui";

function History({ current }: { current: number }) {
  const t = useT();
  const history = useLoad(async (c) => {
    const versions = historyVersions(current);
    const answers = await Promise.all(
      versions.map((v) => c.GET("/v1/audit", { params: { query: { entity: policyAuditEntity(v), limit: 1 } } }).then(({ data }) => ({ v, event: (data?.events[0] ?? null) as ApiAuditEvent | null }))),
    );
    return answers;
  }, `history-${current}`);
  if (history.failure !== null) return <ProblemNotice failure={history.failure} />;
  if (history.data === null) return <Loading />;
  return (
    <table className="text-xs" data-testid="policy-history">
      <thead>
        <tr>
          <th className="pe-3 text-start">{t("ansp.policy.col.version")}</th>
          <th className="pe-3 text-start">{t("ansp.policy.col.at")}</th>
          <th className="pe-3 text-start">{t("ansp.policy.col.by")}</th>
          <th className="text-start">{t("ansp.policy.col.values")}</th>
        </tr>
      </thead>
      <tbody>
        {history.data.map(({ v, event }) => (
          <tr key={v} className="align-top" data-version={v}>
            <td className="pe-3">{v}</td>
            {event === null ? (
              <td colSpan={3}>{t("ansp.policy.history_missing")}</td>
            ) : (
              <>
                <td className="pe-3">
                  <Time iso={event.ts} />
                </td>
                <td className="pe-3">
                  {event.actor_type}:{event.actor_id}
                </td>
                <td className="font-mono">{THRESHOLDS.map((k) => `${k}=${String((event.payload as Record<string, unknown>)[k] ?? "—")}`).join(" ")}</td>
              </>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Editor({ policy, onSaved }: { policy: ApiPolicy; onSaved(p: ApiPolicy): void }) {
  const t = useT();
  const { client } = useConsole();
  const [form, setForm] = useState<PolicyForm>(() => formOf(policy));
  const [problems, setProblems] = useState<FormProblem[]>([]);
  const [pending, setPending] = useState<ApiPolicyUpdate | null>(null);
  const [failure, setFailure] = useState<CallFailure | null>(null);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState<number | null>(null);
  const set = (k: keyof PolicyForm, v: string) => setForm((f) => ({ ...f, [k]: v }));
  const review = () => {
    setSaved(null);
    setFailure(null);
    const built = policyBody(form);
    if ("problems" in built) {
      setProblems(built.problems);
      return;
    }
    setProblems([]);
    setPending(built.body);
  };
  const send = async (body: ApiPolicyUpdate) => {
    setPending(null);
    setBusy(true);
    try {
      const { data } = await client.PUT("/v1/policy", { body });
      if (data !== undefined) {
        setSaved(data.policy_version);
        onSaved(data);
      }
    } catch (err: unknown) {
      setFailure(failureOf(err));
    } finally {
      setBusy(false);
    }
  };
  const problemOf = (k: string) => problems.find((p) => p.field === k);
  const moved = pending === null ? [] : changes(policy, pending);
  return (
    <div className="flex flex-col gap-2" data-testid="policy-editor">
      <div className="grid gap-2 md:grid-cols-2">
        {THRESHOLDS.map((k) => (
          <div key={k} className="flex flex-col gap-0.5">
            <Label htmlFor={`policy-${k}`}>{t("ansp.policy.field", { name: t(`ansp.policy.name.${k}`), unit: t(`ansp.policy.unit.${unitOf(k)}`) })}</Label>
            <Input id={`policy-${k}`} inputMode="decimal" value={form[k]} onChange={(e) => set(k, e.target.value)} data-testid={`policy-input-${k}`} />
            {problemOf(k) !== undefined && <p className="m-0 text-xs text-[var(--us-danger)]">{t(`ansp.policy.problem.${problemOf(k)?.problem ?? "number"}`)}</p>}
          </div>
        ))}
        <div className="flex flex-col gap-0.5">
          <Label htmlFor="policy-zone">{t("ansp.policy.name.default_zone_type")}</Label>
          <select
            id="policy-zone"
            value={form.default_zone_type}
            onChange={(e) => set("default_zone_type", e.target.value)}
            className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1"
          >
            {ZONE_TYPES.map((z) => (
              <option key={z} value={z}>
                {t(`ansp.zone_type.${z}`)}
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-0.5">
          <Label htmlFor="policy-country">{t("ansp.policy.name.country")}</Label>
          <Input id="policy-country" value={form.country} onChange={(e) => set("country", e.target.value)} />
          {problemOf("country") !== undefined && <p className="m-0 text-xs text-[var(--us-danger)]">{t("ansp.policy.problem.country")}</p>}
        </div>
      </div>
      <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.policy.no_reason")}</p>
      <div>
        <Button type="button" size="sm" disabled={busy} onClick={review} data-testid="policy-review">
          {t("ansp.policy.change")}
        </Button>
      </div>
      <ConfirmDialog
        open={pending !== null}
        onCancel={() => setPending(null)}
        titleKey="ansp.policy.confirm.title"
        bodyKey={moved.length === 0 ? "ansp.policy.confirm.same" : "ansp.policy.confirm.body"}
        vars={{ version: policy.policy_version + 1, changes: moved.map((m) => `${m.field}: ${m.from} → ${m.to}`).join("; ") }}
        confirmLabelKey="ansp.policy.confirm.send"
        onConfirm={() => {
          if (pending !== null) void send(pending);
        }}
      />
      {saved !== null && (
        <p role="status" className="m-0 text-sm" data-testid="policy-saved">
          {t("ansp.policy.saved", { version: saved })}
        </p>
      )}
      {failure !== null && <ProblemNotice failure={failure} />}
    </div>
  );
}

export function PolicyPage() {
  const t = useT();
  const { lang } = useLang();
  const { role } = useConsole();
  const loaded = useLoad(async (c) => (await c.GET("/v1/policy")).data ?? null, "policy");
  const [latest, setLatest] = useState<ApiPolicy | null>(null);
  const policy = latest ?? loaded.data;
  return (
    <div className="flex flex-col gap-4">
      <h2 className="m-0 text-lg font-semibold">{t("ansp.policy.title")}</h2>
      {!mayAdminister(role) && <Empty textKey="ansp.policy.role" testId="policy-role" />}
      {loaded.failure !== null && <ProblemNotice failure={loaded.failure} />}
      {policy === null && loaded.failure === null && <Loading />}
      {policy !== null && (
        <>
          <p className="m-0 text-sm" data-testid="policy-version">
            {t("ansp.policy.version", { version: policy.policy_version, by: policy.changed_by })} <Time iso={policy.changed_at} />
          </p>
          <table className="text-sm" data-testid="policy-table">
            <tbody>
              {THRESHOLDS.map((k) => (
                <tr key={k} data-threshold={k}>
                  <td className="pe-4">{t(`ansp.policy.name.${k}`)}</td>
                  <td className="pe-1 text-end font-mono">{policy[k].toLocaleString(lang)}</td>
                  <td>{t(`ansp.policy.unit.${unitOf(k)}`)}</td>
                </tr>
              ))}
              <tr>
                <td className="pe-4">{t("ansp.policy.name.default_zone_type")}</td>
                <td colSpan={2}>{t(`ansp.zone_type.${policy.default_zone_type}`)}</td>
              </tr>
              <tr>
                <td className="pe-4">{t("ansp.policy.name.country")}</td>
                <td colSpan={2} className="font-mono">
                  {policy.country}
                </td>
              </tr>
            </tbody>
          </table>
          {mayAdminister(role) && (
            <Section titleKey="ansp.policy.change_title">
              <Editor key={policy.policy_version} policy={policy} onSaved={setLatest} />
            </Section>
          )}
          <Section titleKey="ansp.policy.history">
            <History current={policy.policy_version} />
          </Section>
        </>
      )}
    </div>
  );
}
