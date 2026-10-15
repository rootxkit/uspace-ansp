"use client";

// /<locale>/restrictions/new: plan a restriction on the map (ATS.TR.237(a),
// 02 F2). The supervisor draws the area with the kit's drawing tool
// (layers/DrawLayer: a click per polygon vertex or for a circle's centre,
// a drag to move a point) or types it (form/OutlineFields, the keyboard
// path: vertices, or a circle's centre and radius in metres); a circle's
// outline on the map is the one the API drew (GET /v1/outlines/circle,
// docs/PLAN.md section 15 row 53), the centre alone until it has. Then
// the lower and upper limits with their reference (AMSL
// or WGS84; AGL is shown as unavailable with the API's reason, D3), the
// window in UTC, the reason, and the U-space airspace the restriction
// lies in. The kit's form checks shape only; the API judges everything
// else and its problems are put on their fields, the rest listed with
// their path. A window longer than CstrMaxDurationHours comes back as the
// chain of re-issues the API proposes, shown and planned only when the
// supervisor ticks it. Nothing is sent before the confirmation that says
// what will be sent to whom.
import { useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import type { z } from "zod";
import { CheckboxField, EnumField, Form, NumberField, OutlineFields, TextField, UTCDateTimeField, emptyOutline } from "@rootxkit/uspace-ui/form";
import { ConfirmDialog } from "@rootxkit/uspace-ui/form";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { DrawLayer } from "@rootxkit/uspace-ui/layers";
import { MapPanel } from "@rootxkit/uspace-ui/ui";
import type { DrawOutline, FieldError } from "@rootxkit/uspace-ui/model";
import { chainProposal, failureOf, type CallFailure } from "../api/client";
import type { components } from "../api/types";
import { toView } from "./adapt";
import { ConsoleMap } from "./ConsoleMap";
import { useConsole } from "./context";
import { MAX_VERTICES, useCircleOutline } from "./outline";
import { planBody, planSchema, VERTICAL_REFS, ZONE_TYPES, type PlanValues } from "./plan";
import { referenceAfter, referenceFor } from "./reference";
import { maySupervise } from "./roles";
import { ConsolePageHeader, Empty } from "./ui";
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
  const [outline, setOutline] = useState<DrawOutline>(() => emptyOutline("polygon"));
  const circle = useCircleOutline(client, outline);
  const [pending, setPending] = useState<Pending | null>(null);
  const [chain, setChain] = useState<FieldError[]>([]);
  const [failure, setFailure] = useState<CallFailure | null>(null);
  // One reference per editor: a resend of the same plan is answered with
  // the restriction first created (api/openapi.yaml createRestriction).
  const ref = useRef<string>("");

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
    confirm_chain: false,
  };

  const onSubmit = (values: PlanValues): Promise<FieldError[] | undefined> => {
    setFailure(null);
    const built = planBody(values, outline, {
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

  if (!maySupervise(role)) {
    return (
      <div className="flex flex-col gap-6">
        <ConsolePageHeader titleKey="ansp.editor.title" descriptionKey="ansp.editor.description" />
        <Empty textKey="ansp.editor.role" testId="editor-role" />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
    <ConsolePageHeader titleKey="ansp.editor.title" descriptionKey="ansp.editor.description" />
    <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
      <div className="flex flex-col gap-3 rounded-lg border border-border bg-card p-5 shadow-panel lg:w-[45%]">
        <OutlineFields outline={outline} onChange={setOutline} maxVertices={MAX_VERTICES} circleOutlineShown={circle.kind === "drawn"} legendKey="ansp.editor.area" />
        {circle.kind === "refused" && (
          <p role="status" className="m-0 text-xs" data-testid="circle-outline-refused">
            {t("ansp.editor.circle_outline_refused")}
          </p>
        )}
        <Form schema={planSchema} defaults={defaults} onSubmit={onSubmit} submitLabelKey="ansp.editor.submit" successKey="ansp.editor.planned">
          <TextField name="uspace_airspace_id" labelKey="ansp.field.uspace_airspace_id" hintKey="ansp.field.uspace_airspace_id.hint" required />
          <EnumField name="zone_type" labelKey="ansp.field.zone_type" values={ZONE_TYPES} i18nPrefix="ansp.zone_type" required />
          <NumberField name="lower_m" labelKey="ansp.field.lower_m" unit="form.unit.m" required />
          <EnumField name="lower_ref" labelKey="ansp.field.lower_ref" values={VERTICAL_REFS} i18nPrefix="ansp.vertical_ref" required />
          <NumberField name="upper_m" labelKey="ansp.field.upper_m" unit="form.unit.m" required />
          <EnumField name="upper_ref" labelKey="ansp.field.upper_ref" values={VERTICAL_REFS} i18nPrefix="ansp.vertical_ref" required />
          <p className="m-0 text-xs text-muted-foreground" data-testid="agl-unavailable">
            {t("ansp.editor.agl_unavailable")}
          </p>
          <UTCDateTimeField name="starts_at" labelKey="ansp.field.starts_at" required />
          <UTCDateTimeField name="ends_at" labelKey="ansp.field.ends_at" required />
          <TextField name="reason_text" labelKey="ansp.field.reason_text" hintKey="ansp.field.reason_text.hint" required />
          {chain.length > 0 && (
            <div role="alert" className="flex flex-col gap-1 rounded-lg border border-status-critical-border bg-status-critical-soft p-3 text-sm" data-testid="chain-proposal">
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
      <MapPanel
        title={t("ansp.map.title")}
        className="min-w-0 flex-1 lg:sticky lg:top-20"
        mapClassName="h-[70vh]"
        footer={<p className="m-0 text-xs text-muted-foreground">{t("ansp.editor.map_hint")}</p>}
      >
        <ConsoleMap restrictions={views} fill>
          <DrawLayer
            id="ansp-draw"
            outline={outline}
            onChange={setOutline}
            maxVertices={MAX_VERTICES}
            circleOutline={circle.kind === "drawn" ? circle.outline : null}
          />
        </ConsoleMap>
      </MapPanel>
    </div>
    </div>
  );
}
