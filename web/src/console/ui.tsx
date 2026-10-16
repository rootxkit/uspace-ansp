"use client";

// The console's small display parts: a time in UTC laid out for the
// page's language, a state badge, the API's refusal shown in
// full, the confirm-with-a-reason act every audited operation goes
// through, and the empty state that says why it is empty.
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useSyncExternalStore, type ReactNode } from "react";
import { createTranslator, useLang, useT, type Translate } from "@rootxkit/uspace-ui/i18n";
import { ConfirmDialog } from "@rootxkit/uspace-ui/form";
import type { StatusTone } from "@rootxkit/uspace-ui/theme";
import { Button, PageHeader, Panel, StatusBadge, type Crumb, type LinkRenderer } from "@rootxkit/uspace-ui/ui";
import { catalogues } from "../i18n/catalogues";
import { failureOf, type CallFailure } from "../api/client";
import { navItemOf } from "./roles";

function noSubscribe(): () => void {
  return () => undefined;
}

/** True in the browser after hydration; false while rendering on the server. */
export function useInBrowser(): boolean {
  return useSyncExternalStore(
    noSubscribe,
    () => true,
    () => false,
  );
}

function two(n: number): string {
  return String(n).padStart(2, "0");
}

/**
 * An RFC 3339 instant in UTC, laid out for the page's language from the
 * catalogue ("15 Oct 2026, 22:07:49 UTC", "15 ოქტ. 2026, 22:07:49 UTC"):
 * the console says UTC everywhere, never the viewer's zone. The month
 * names are the catalogue's, not the browser's: a browser without
 * Georgian locale data formats ka-GE in English. Null when the value is
 * not a time.
 */
export function utcTime(iso: string, t: Translate): string | null {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  const d = new Date(ms);
  return t("ansp.time.utc", {
    day: d.getUTCDate(),
    month: t(`ansp.time.month.${d.getUTCMonth() + 1}`),
    year: d.getUTCFullYear(),
    time: `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())}`,
  });
}

/** An instant as UTC text in the viewer's language, or a dash. */
export function utcText(iso: string | null | undefined, lang: "ka" | "en"): string {
  if (iso === null || iso === undefined || iso === "") return "—";
  return utcTime(iso, createTranslator(lang, catalogues)) ?? iso;
}

/** A time in UTC in the page's language; its RFC 3339 value is the title. */
export function Time({ iso }: { iso: string | null | undefined }) {
  const t = useT();
  if (iso === null || iso === undefined || iso === "") return <span>—</span>;
  return (
    <time dateTime={iso} title={iso} className="whitespace-nowrap" data-testid="utc-time">
      {utcTime(iso, t) ?? iso}
    </time>
  );
}

/** The vars with their instants (`at`, `since`, `next`, `status_at`) as UTC text. */
export function timesShown(vars: Record<string, string | number>, lang: "ka" | "en"): Record<string, string | number> {
  const out = { ...vars };
  for (const k of ["at", "since", "next", "status_at"]) {
    const v = out[k];
    if (typeof v === "string") out[k] = utcText(v, lang);
  }
  return out;
}

/**
 * The kit's tone per restriction state. A tone repeats the state the
 * badge says in words (WCAG 1.4.1); it is not a legend colour and judges
 * nothing. Display-only.
 */
export const RESTRICTION_TONE: Readonly<Record<string, StatusTone>> = {
  planned: "info",
  active: "warning",
  ended: "neutral",
  cancelled: "neutral",
};

/** A restriction's state as a badge; a state this console does not know is shown as sent. */
export function StateBadge({ state }: { state: string }) {
  const t = useT();
  const tone = RESTRICTION_TONE[state];
  return (
    <StatusBadge tone={tone ?? "neutral"} variant={tone === undefined ? "outline" : "soft"} data-state={state} data-testid="restriction-state">
      {tone === undefined ? state : t(`ansp.restriction.state.${state}`)}
    </StatusBadge>
  );
}

/** next/link for the kit's frame components. */
export const renderLink: LinkRenderer = (p) => <Link {...p} />;

/**
 * The top of a console page: the kit's PageHeader with the trail from
 * the sidebar's group to this page, the page's h1, what it is about, and
 * its actions. `title` replaces the catalogue title (a restriction's
 * identifier); the trail then links the list it belongs to.
 */
export function ConsolePageHeader(props: {
  titleKey: string;
  title?: ReactNode;
  descriptionKey?: string;
  description?: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
}) {
  const t = useT();
  const { lang } = useLang();
  const pathname = usePathname();
  const path = pathname.replace(/^\/(ka|en)(?=\/|$)/, "");
  const item = navItemOf(path);
  const crumbs: Crumb[] = [];
  if (item !== null) {
    crumbs.push({ label: t(`ansp.nav.group.${item.group}`) });
    if (path === item.path) crumbs.push({ label: t(item.labelKey) });
    else crumbs.push({ label: t(item.labelKey), href: `/${lang}${item.path}` }, { label: props.title ?? t(props.titleKey) });
  }
  const description = props.description ?? (props.descriptionKey === undefined ? undefined : t(props.descriptionKey));
  return (
    <PageHeader
      title={props.title ?? t(props.titleKey)}
      breadcrumbs={crumbs}
      renderLink={renderLink}
      {...(description === undefined ? {} : { description })}
      {...(props.meta === undefined ? {} : { meta: props.meta })}
      {...(props.actions === undefined ? {} : { actions: props.actions })}
    />
  );
}

/**
 * A refused or failed call, visibly: the status, what it means for the
 * operator (a 403 names the role, a 401 says sign in again), and the
 * API's title and detail with its field problems. Never a silent empty
 * table.
 */
export function ProblemNotice({ failure }: { failure: CallFailure }) {
  const t = useT();
  const p = failure.problem;
  const lead =
    failure.status === 0
      ? t("ansp.problem.unreachable")
      : failure.status === 401
        ? t("ansp.problem.signed_out")
        : failure.status === 403
          ? t("ansp.problem.forbidden")
          : failure.status === 404
            ? t("ansp.problem.not_found")
            : failure.status === 501
              ? t("ansp.problem.not_served")
            : failure.slug === "cis_stale"
              ? t("ansp.problem.cis_stale")
              : t("ansp.problem.refused", { status: failure.status });
  return (
    <div
      role="alert"
      data-status={failure.status}
      data-slug={failure.slug ?? ""}
      className="rounded-lg border border-status-critical-border bg-status-critical-soft p-3 text-sm text-foreground"
    >
      <p className="m-0 font-semibold text-status-critical">{lead}</p>
      {p !== null && (
        <p className="m-0 mt-1">
          <span>{p.title}</span>
          {p.detail !== null && p.detail !== "" && <span>: {p.detail}</span>}
          <span className="ms-2 text-xs text-muted-foreground">({failure.status})</span>
        </p>
      )}
      {p !== null && p.errors.length > 0 && (
        <ul className="m-0 mt-1 ps-5">
          {p.errors.map((e, i) => (
            <li key={`${e.field}-${i}`}>
              <code>{e.field}</code>: {e.reason}
            </li>
          ))}
        </ul>
      )}
      {p?.truncated === true && <p className="m-0 mt-1 text-xs">{t("ansp.problem.truncated")}</p>}
      {failure.retryAfterS !== null && failure.retryAfterS > 0 && (
        <p className="m-0 mt-1">{t("ansp.problem.retry_after", { seconds: failure.retryAfterS })}</p>
      )}
    </div>
  );
}

/** The largest reason the API takes (ReasonRequest.reason maxLength). */
export const REASON_MAX_CHARS = 500;

/**
 * An audited act: a button that opens the kit's ConfirmDialog with what
 * will be sent to whom spelled out and a required reason, then
 * `act(reason)`. The API's answer is shown under the button: its refusal
 * in full (a 403 included), or `doneKey` once it is done.
 */
export function ReasonAction(props: {
  labelKey: string;
  titleKey: string;
  bodyKey: string;
  vars?: Record<string, string | number>;
  destructive?: boolean;
  doneKey: string;
  disabled?: boolean;
  act(reason: string): Promise<unknown>;
  onDone?(): void;
  testId?: string;
}) {
  const t = useT();
  const [failure, setFailure] = useState<CallFailure | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const run = async (reason: string) => {
    setFailure(null);
    setDone(false);
    if (reason.length > REASON_MAX_CHARS) {
      setFailure({
        status: 400,
        problem: {
          type: "",
          title: t("ansp.action.reason_too_long", { max: REASON_MAX_CHARS }),
          status: 400,
          detail: null,
          instance: null,
          errors: [],
        },
        slug: null,
        retryAfterS: null,
        fieldErrors: [],
      });
      return;
    }
    setBusy(true);
    try {
      await props.act(reason);
      setDone(true);
      props.onDone?.();
    } catch (err: unknown) {
      setFailure(failureOf(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex flex-col items-start gap-1">
      <ConfirmDialog
        titleKey={props.titleKey}
        bodyKey={props.bodyKey}
        {...(props.vars === undefined ? {} : { vars: props.vars })}
        reason={{ required: true, minLength: 1 }}
        destructive={props.destructive ?? false}
        onConfirm={(reason) => void run(reason ?? "")}
        trigger={
          <Button type="button" size="sm" variant="outline" disabled={busy || props.disabled === true} data-testid={props.testId}>
            {t(props.labelKey)}
          </Button>
        }
      />
      {done && (
        <p role="status" className="m-0 text-xs">
          {t(props.doneKey, props.vars)}
        </p>
      )}
      {failure !== null && <ProblemNotice failure={failure} />}
    </div>
  );
}

/** A section of a page: the kit's Panel, named by its heading (an h2 under the page's h1). */
export function Section({
  titleKey,
  vars,
  descriptionKey,
  actions,
  children,
  className,
}: {
  titleKey: string;
  vars?: Record<string, string | number>;
  descriptionKey?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  const t = useT();
  return (
    <Panel
      title={t(titleKey, vars)}
      {...(descriptionKey === undefined ? {} : { description: t(descriptionKey) })}
      {...(actions === undefined ? {} : { actions })}
      {...(className === undefined ? {} : { className })}
      bodyClassName="flex flex-col gap-2"
    >
      {children}
    </Panel>
  );
}

/** "Loading" while the first answer is out. */
export function Loading() {
  const t = useT();
  return (
    <p role="status" className="m-0 animate-pulse text-sm text-muted-foreground motion-reduce:animate-none">
      {t("ansp.loading")}
    </p>
  );
}

/** An empty state that says why it is empty (E-02): never a blank page. */
export function Empty({ textKey, vars, testId }: { textKey: string; vars?: Record<string, string | number>; testId?: string }) {
  const t = useT();
  return (
    <p role="status" data-testid={testId} className="m-0 rounded-lg border border-dashed border-border-strong bg-surface-sunken px-4 py-3 text-sm">
      {t(textKey, vars)}
    </p>
  );
}
