"use client";

// /<locale>/restrictions/new: plan a restriction on the map (ATS.TR.237(a),
// 02 F2). The supervisor draws a polygon (a click per vertex, or the
// vertex list typed) or a circle (a click for the centre and a radius in
// metres), enters the lower and upper limits with their reference (AMSL
// or WGS84; AGL is shown as unavailable with the API's reason, D3), the
// window in UTC, the reason, and the U-space airspace the restriction
// lies in. The kit's form checks shape only; the API judges everything
// else and its problems are put on their fields, the rest listed with
// their path. A window longer than CstrMaxDurationHours comes back as the
// chain of re-issues the API proposes, shown and planned only when the
// supervisor ticks it. Nothing is sent before the confirmation that says
// what will be sent to whom.
import { useCallback, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import type { z } from "zod";
import { CheckboxField, EnumField, Form, NumberField, TextField, UTCDateTimeField } from "@rootxkit/uspace-ui/form";
import { ConfirmDialog } from "@rootxkit/uspace-ui/form";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import type { FieldError } from "@rootxkit/uspace-ui/model";
import { Button, Label, Textarea } from "@rootxkit/uspace-ui/ui";
import { chainProposal, failureOf, type CallFailure } from "../api/client";
import type { components } from "../api/types";
import { toView } from "./adapt";
import { ConsoleMap, DraftLayer } from "./ConsoleMap";
import { useConsole } from "./context";
import { parseVertices, roundClick, verticesText, type Position } from "./draft";
import { planBody, planSchema, VERTICAL_REFS, ZONE_TYPES, type AreaMode, type PlanValues } from "./plan";
import { referenceAfter, referenceFor } from "./reference";
import { maySupervise } from "./roles";
import { Empty } from "./ui";
import { useRestrictions } from "./useRestrictions";

type ApiRestrictionCreate = components["schemas"]["RestrictionCreate"];

interface Pending {
  body: ApiRestrictionCreate;
  resolve(result: FieldError[] | undefined): void;
  reject(err: unknown): void;
}

export function RestrictionEditorPage() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const { client, role } = useConsole();
  const others = useRestrictions("active");
  const views = useMemo(() => (others.restrictions ?? []).map((r) => toView(r, lang)), [others.restrictions, lang]);
  const [mode, setMode] = useState<AreaMode>("polygon");
  const [vertices, setVertices] = useState<Position[]>([]);
  const [text, setText] = useState("");
  const [textProblem, setTextProblem] = useState<string | null>(null);
  const [centre, setCentre] = useState<Position | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [chain, setChain] = useState<FieldError[]>([]);
  const [failure, setFailure] = useState<CallFailure | null>(null);
  // One reference per editor: a resend of the same plan is answered with
  // the restriction first created (api/openapi.yaml createRestriction).
  const ref = useRef<string>("");

  const onMapClick = useCallback(
    (at: Position) => {
      const p = roundClick(at);
      if (mode === "circle") {
        setCentre(p);
        return;
      }
      setVertices((vs) => {
        const next = [...vs, p];
        setText(verticesText(next));
        setTextProblem(null);
        return next;
      });
    },
    [mode],
  );

  const onText = (v: string) => {
    setText(v);
    const parsed = parseVertices(v);
    if ("vertices" in parsed) {
      setVertices(parsed.vertices);
      setTextProblem(null);
    } else {
      setTextProblem(t(`ansp.editor.vertices.${parsed.problem}`, { line: parsed.line }));
    }
  };

  const defaults: z.input<typeof planSchema> = {
    uspace_airspace_id: "",
    zone_type: "PROHIBITED",
    lower_m: null as unknown as number,
    lower_ref: "AMSL",
    upper_m: null as unknown as number,
    upper_ref: "AMSL",
    starts_at: "",
    ends_at: "",
    reason_text: "",
    radius_m: null,
    confirm_chain: false,
  };

  const onSubmit = (values: PlanValues): Promise<FieldError[] | undefined> => {
    setFailure(null);
    const built = planBody(values, mode, vertices, centre, {
      polygon: t("ansp.editor.polygon_required"),
      centre: t("ansp.editor.centre_required"),
      radius: t("ansp.editor.radius_required"),
    });
    if ("errors" in built) return Promise.resolve(built.errors);
    ref.current = referenceFor(ref.current);
    return new Promise((resolve, reject) => setPending({ body: built.body, resolve, reject }));
  };

  const send = async (p: Pending) => {
    setPending(null);
    try {
      const { data } = await client.POST("/v1/restrictions", {
        params: { header: { "Idempotency-Key": ref.current } },
        body: p.body,
      });
      setChain([]);
      p.resolve(undefined);
      if (data !== undefined) router.push(`/${lang}/restrictions/${data.id}`);
    } catch (err: unknown) {
      const f = failureOf(err);
      setChain(chainProposal(f));
      // A refusal spends the reference (the next body is another plan);
      // no answer, a 502 or a 504 keeps it for the retry (reference.ts).
      ref.current = referenceAfter(ref.current, f);
      setFailure(f);
      p.reject(err);
    }
  };

  if (!maySupervise(role)) return <Empty textKey="ansp.editor.role" testId="editor-role" />;

  const closedDraft = mode === "polygon";
  const drawn = mode === "polygon" ? vertices : centre === null ? [] : [centre];

  return (
    <div className="flex flex-col gap-4 lg:flex-row">
      <div className="flex flex-col gap-2 lg:w-[45%]">
        <h2 className="m-0 text-lg font-semibold">{t("ansp.editor.title")}</h2>
        <fieldset className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-2">
          <legend className="px-1 text-sm font-semibold">{t("ansp.editor.area")}</legend>
          <div className="flex gap-3 text-sm" role="radiogroup" aria-label={t("ansp.editor.mode")}>
            {(["polygon", "circle"] as const).map((m) => (
              <label key={m} className="flex items-center gap-1">
                <input type="radio" name="area-mode" value={m} checked={mode === m} onChange={() => setMode(m)} data-testid={`mode-${m}`} />
                {t(`ansp.editor.mode.${m}`)}
              </label>
            ))}
          </div>
          <p className="m-0 text-xs text-[var(--us-text-muted)]">{t(mode === "polygon" ? "ansp.editor.hint_polygon" : "ansp.editor.hint_circle")}</p>
          {mode === "polygon" ? (
            <div className="flex flex-col gap-1">
              <Label htmlFor="vertices">{t("ansp.editor.vertices")}</Label>
              <Textarea id="vertices" rows={6} value={text} onChange={(e) => onText(e.target.value)} className="font-mono text-xs" data-testid="vertices" />
              {textProblem !== null && (
                <p role="alert" className="m-0 text-xs text-[var(--us-danger)]">
                  {textProblem}
                </p>
              )}
              <p className="m-0 text-xs" data-testid="vertex-count">
                {t("ansp.editor.vertex_count", { count: vertices.length })}
              </p>
              <div className="flex gap-2">
                <Button type="button" size="sm" variant="outline" disabled={vertices.length === 0} onClick={() => onText(verticesText(vertices.slice(0, -1)))}>
                  {t("ansp.editor.undo")}
                </Button>
                <Button type="button" size="sm" variant="outline" disabled={vertices.length === 0} onClick={() => onText("")}>
                  {t("ansp.editor.clear")}
                </Button>
              </div>
            </div>
          ) : (
            <p className="m-0 text-sm" data-testid="centre">
              {centre === null ? t("ansp.editor.centre_none") : t("ansp.editor.centre", { lng: centre[0], lat: centre[1] })}
            </p>
          )}
        </fieldset>
        <Form schema={planSchema} defaults={defaults} onSubmit={onSubmit} submitLabelKey="ansp.editor.submit" successKey="ansp.editor.planned">
          {mode === "circle" && <NumberField name="radius_m" labelKey="ansp.field.radius_m" unit="form.unit.m" required />}
          <TextField name="uspace_airspace_id" labelKey="ansp.field.uspace_airspace_id" hintKey="ansp.field.uspace_airspace_id.hint" required />
          <EnumField name="zone_type" labelKey="ansp.field.zone_type" values={ZONE_TYPES} i18nPrefix="ansp.zone_type" required />
          <NumberField name="lower_m" labelKey="ansp.field.lower_m" unit="form.unit.m" required />
          <EnumField name="lower_ref" labelKey="ansp.field.lower_ref" values={VERTICAL_REFS} i18nPrefix="ansp.vertical_ref" required />
          <NumberField name="upper_m" labelKey="ansp.field.upper_m" unit="form.unit.m" required />
          <EnumField name="upper_ref" labelKey="ansp.field.upper_ref" values={VERTICAL_REFS} i18nPrefix="ansp.vertical_ref" required />
          <p className="m-0 text-xs text-[var(--us-text-muted)]" data-testid="agl-unavailable">
            {t("ansp.editor.agl_unavailable")}
          </p>
          <UTCDateTimeField name="starts_at" labelKey="ansp.field.starts_at" required />
          <UTCDateTimeField name="ends_at" labelKey="ansp.field.ends_at" required />
          <TextField name="reason_text" labelKey="ansp.field.reason_text" hintKey="ansp.field.reason_text.hint" required />
          {chain.length > 0 && (
            <div role="alert" className="flex flex-col gap-1 rounded border border-[var(--us-danger)] p-2 text-sm" data-testid="chain-proposal">
              <p className="m-0 font-semibold">{t("ansp.editor.chain.title", { count: chain.length })}</p>
              <ol className="m-0 ps-5">
                {chain.map((c) => (
                  <li key={c.field}>
                    <code>{c.field}</code>: {c.reason}
                  </li>
                ))}
              </ol>
              <p className="m-0">{t("ansp.editor.chain.confirm_hint")}</p>
            </div>
          )}
          <CheckboxField name="confirm_chain" labelKey="ansp.field.confirm_chain" hintKey="ansp.field.confirm_chain.hint" />
        </Form>
        {failure !== null && failure.slug === "cis_stale" && <Empty textKey="ansp.editor.cis_stale" testId="editor-cis-stale" />}
        <ConfirmDialog
          open={pending !== null}
          onCancel={() => {
            // Cancelled (button, Escape, outside click): nothing was sent.
            pending?.resolve([{ field: "", reason: t("ansp.editor.not_sent") }]);
            setPending(null);
          }}
          titleKey="ansp.editor.confirm.title"
          bodyKey="ansp.editor.confirm.body"
          vars={{
            airspace: pending?.body.uspace_airspace_id ?? "",
            chain: pending?.body.confirm_chain === true ? t("ansp.editor.confirm.chain") : "",
          }}
          confirmLabelKey="ansp.editor.confirm.send"
          onConfirm={() => {
            if (pending !== null) void send(pending);
          }}
        />
      </div>
      <div className="flex flex-1 flex-col gap-1">
        <ConsoleMap restrictions={views} className="h-[70vh]">
          <DraftLayer vertices={drawn} closed={closedDraft} onClick={onMapClick} />
        </ConsoleMap>
        <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("ansp.editor.map_hint")}</p>
      </div>
    </div>
  );
}
