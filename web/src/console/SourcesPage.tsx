"use client";

// /<locale>/sources: the source switches (04 §3.6, U-15; SC-08 steps 6
// and 7 in the console). Every session reads them: each switch with who
// set it, when and why, and the adapter's own state beside it (B-11:
// disabled is not silent). An administrator switches the whole manned
// type or one adapter off or on with a required reason; the API's answer
// is shown as it said it, its 503 "switch store unavailable, nothing
// changed" included, word for word. Any other role sees no switch
// control, and a 403 the API answers anyway is shown as the refusal it is.
import Link from "next/link";
import { useEffect } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { statusLine, switchFor, TYPE_INSTANCE } from "./adapters";
import { useConsole, useLoad } from "./context";
import { mayAdminister } from "./roles";
import { isEnabled, SOURCE_TYPE, switchAuditEntity, switchBody, switchRows } from "./sources";
import { Empty, Loading, ProblemNotice, ReasonAction, Time, timesShown } from "./ui";

/** How often the page reads the switches again. Display-only. */
export const READ_PERIOD_MS = 10_000;

export function SourcesPage() {
  const t = useT();
  const { lang } = useLang();
  const { client, role } = useConsole();
  const sources = useLoad(async (c) => (await c.GET("/v1/sources")).data?.sources ?? [], "sources");
  const adapters = useLoad(async (c) => (await c.GET("/v1/adapters")).data?.adapters ?? [], "adapters");
  const { reload: reloadSources } = sources;
  const { reload: reloadAdapters } = adapters;
  useEffect(() => {
    const id = setInterval(() => {
      reloadSources();
      reloadAdapters();
    }, READ_PERIOD_MS);
    return () => clearInterval(id);
  }, [reloadSources, reloadAdapters]);
  const admin = mayAdminister(role);
  const rows = sources.data === null ? null : switchRows(adapters.data ?? [], sources.data);

  return (
    <div className="flex flex-col gap-4">
      <h2 className="m-0 text-lg font-semibold">{t("ansp.sources.title")}</h2>
      <p className="m-0 text-xs text-[var(--us-text-muted)]">{t(admin ? "ansp.sources.intro_admin" : "ansp.sources.intro_reader")}</p>
      {sources.failure !== null && <ProblemNotice failure={sources.failure} />}
      {adapters.failure !== null && (
        <div>
          <p className="m-0 text-sm font-semibold">{t("ansp.sources.adapters_unavailable")}</p>
          <ProblemNotice failure={adapters.failure} />
        </div>
      )}
      {rows === null && sources.failure === null && <Loading />}
      {rows !== null && (
        <ul className="m-0 flex flex-col gap-2 p-0" data-testid="switches">
          {rows.map((row) => {
            const enabled = isEnabled(row);
            const name = row.instance === TYPE_INSTANCE ? t("ansp.sources.type_all") : (row.adapter?.display_name ?? row.instance);
            const line = row.adapter === null ? null : statusLine(row.adapter, switchFor(row.adapter, sources.data ?? []));
            return (
              <li
                key={row.instance}
                className={`flex list-none flex-col gap-1 rounded border p-3 text-sm ${enabled ? "border-[var(--us-border)]" : "border-[var(--us-danger)]"}`}
                data-testid="switch"
                data-instance={row.instance}
                data-enabled={enabled}
              >
                <p className="m-0 font-semibold">
                  {name} <code className="font-normal">{`${SOURCE_TYPE}/${row.instance}`}</code>
                </p>
                <p className={`m-0 ${enabled ? "" : "font-semibold text-[var(--us-danger)]"}`} data-testid="switch-state">
                  {row.control === null
                    ? t("ansp.sources.none_set")
                    : t(row.control.enabled ? "ansp.sources.enabled_by" : "ansp.sources.disabled_by", {
                        ...timesShown({ at: row.control.changed_at }, lang),
                        actor: row.control.actor,
                        reason: row.control.reason,
                        version: row.control.version,
                      })}
                </p>
                {line !== null && <p className="m-0 text-xs">{t(line.key, timesShown(line.vars, lang))}</p>}
                {row.adapter === null && row.instance !== TYPE_INSTANCE && <p className="m-0 text-xs">{t("ansp.sources.not_registered")}</p>}
                {row.control !== null && (
                  <p className="m-0 text-xs text-[var(--us-text-muted)]">
                    {t("ansp.sources.changed")} <Time iso={row.control.changed_at} />
                    {admin && (
                      <>
                        {" · "}
                        <Link href={`/${lang}/audit?entity=${encodeURIComponent(switchAuditEntity(row.instance))}`} className="underline">
                          {t("ansp.sources.audit")}
                        </Link>
                      </>
                    )}
                  </p>
                )}
                {admin && (
                  <ReasonAction
                    labelKey={enabled ? "ansp.sources.disable" : "ansp.sources.enable"}
                    titleKey={enabled ? "ansp.sources.disable_title" : "ansp.sources.enable_title"}
                    bodyKey={row.instance === TYPE_INSTANCE ? (enabled ? "ansp.sources.disable_type_body" : "ansp.sources.enable_type_body") : enabled ? "ansp.sources.disable_body" : "ansp.sources.enable_body"}
                    vars={{ instance: row.instance }}
                    destructive={enabled}
                    doneKey={enabled ? "ansp.sources.disabled_done" : "ansp.sources.enabled_done"}
                    act={(reason) =>
                      client.PUT("/v1/sources/{type}/{instance}", {
                        params: { path: { type: SOURCE_TYPE, instance: row.instance } },
                        body: switchBody(!enabled, reason),
                      })
                    }
                    onDone={() => {
                      reloadSources();
                      reloadAdapters();
                    }}
                    testId={`switch-${row.instance}`}
                  />
                )}
              </li>
            );
          })}
        </ul>
      )}
      {rows !== null && rows.length === 1 && adapters.data !== null && <Empty textKey="ansp.sources.no_adapters" testId="sources-no-adapters" />}
    </div>
  );
}
