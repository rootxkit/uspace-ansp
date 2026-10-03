"use client";

// /<locale>/adapters: every surveillance adapter of the manned feed, as
// the API states it: configured and never heard, running with its last
// frame, silent since T, or disabled by whom, when and why (B-11: a
// disabled adapter looks different from a silent one), with its counters
// by their snake_case names. Read again every READ_PERIOD_MS.
import { useEffect } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { switchFor, statusLine } from "./adapters";
import { useLoad } from "./context";
import { Empty, Loading, ProblemNotice, Time, timesShown } from "./ui";

/** How often the page reads the adapters again. Display-only. */
export const READ_PERIOD_MS = 10_000;

export function AdaptersPage() {
  const t = useT();
  const { lang } = useLang();
  const adapters = useLoad(async (c) => (await c.GET("/v1/adapters")).data?.adapters ?? [], "adapters");
  const sources = useLoad(async (c) => (await c.GET("/v1/sources")).data?.sources ?? [], "sources");
  const { reload: reloadAdapters } = adapters;
  const { reload: reloadSources } = sources;
  useEffect(() => {
    const id = setInterval(() => {
      reloadAdapters();
      reloadSources();
    }, READ_PERIOD_MS);
    return () => clearInterval(id);
  }, [reloadAdapters, reloadSources]);

  return (
    <div className="flex flex-col gap-4">
      <h2 className="m-0 text-lg font-semibold">{t("ansp.adapters.title")}</h2>
      {adapters.failure !== null && <ProblemNotice failure={adapters.failure} />}
      {sources.failure !== null && (
        <div>
          <p className="m-0 text-sm font-semibold">{t("ansp.adapters.sources_unavailable")}</p>
          <ProblemNotice failure={sources.failure} />
        </div>
      )}
      {adapters.data === null && adapters.failure === null && <Loading />}
      {adapters.data !== null && adapters.data.length === 0 && <Empty textKey="ansp.adapters.none" testId="adapters-none" />}
      {adapters.data !== null && adapters.data.length > 0 && (
        <ul className="m-0 grid gap-3 p-0 md:grid-cols-2" data-testid="adapters">
          {adapters.data.map((a) => {
            const line = statusLine(a, switchFor(a, sources.data ?? []));
            const counters = Object.entries(a.counters).sort(([x], [y]) => x.localeCompare(y));
            return (
              <li key={a.id} className="list-none rounded border border-[var(--us-border)] p-3 text-sm" data-adapter={a.id} data-status={a.status}>
                <p className="m-0 font-semibold">
                  {a.display_name} <code className="font-normal">{a.id}</code>
                </p>
                <p className="m-0 text-xs text-[var(--us-text-muted)]">
                  {t(`ansp.adapters.kind.${a.kind}`)} · {t(`ansp.adapters.class.${a.source_class}`)}
                </p>
                <p className={`m-0 ${line.attention ? "font-semibold text-[var(--us-danger)]" : ""}`} data-testid="adapter-status">
                  {t(line.key, timesShown(line.vars, lang))}
                </p>
                <p className="m-0 text-xs">
                  {t("ansp.adapters.last_frame")} <Time iso={a.last_frame_at} />
                </p>
                {counters.length === 0 ? (
                  <p className="m-0 text-xs">{t("ansp.adapters.no_counters")}</p>
                ) : (
                  <table className="mt-1 text-xs">
                    <tbody>
                      {counters.map(([name, n]) => (
                        <tr key={name}>
                          <td className="pe-3 font-mono">{name}</td>
                          <td className="text-end">{n.toLocaleString(lang)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
