"use client";

// The status bar, where the supervisor looks first (CLAUDE.md rule 4,
// M29): the restriction stream's state from its console/status/v1 frames
// (live, connecting, down since T), what the server says is degraded, the
// CIS version and the age of its projection, and the API's NATS state.
// A 4401 close or a 401 answer is "signed out, sign in again" with the
// way back; nothing here is a verdict of its own.
import Link from "next/link";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { useNowMs } from "@rootxkit/uspace-ui/live";
import { DegradedBanner, FeedStatusBar } from "@rootxkit/uspace-ui/status";
import { loginPath, useConsole } from "./context";

/** How often ages on the bar are redrawn. Display-only. */
const TICK_MS = 1000;

export function StatusBar() {
  const t = useT();
  const { lang } = useLang();
  const { feed, signedOut } = useConsole();
  const nowMs = useNowMs(TICK_MS);
  const { cisVersion, cisAgeS, nats } = feed.extras;
  return (
    <section
      aria-label={t("ansp.status.label")}
      data-testid="status-bar"
      data-connection={feed.connection}
      className="flex flex-col gap-1 border-b border-[var(--us-border)] bg-[var(--us-surface-sunken)] px-4 py-2 text-xs"
    >
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <FeedStatusBar status={feed} nowMs={nowMs} />
        {feed.connection === "live" && (
          <span data-testid="cis-status">
            {cisVersion === null
              ? t("ansp.status.cis_none")
              : t("ansp.status.cis", { version: cisVersion, age: cisAgeS === null ? "—" : Math.round(cisAgeS) })}
          </span>
        )}
        {feed.connection === "live" && nats !== null && <span>{t("ansp.status.nats", { state: nats })}</span>}
      </div>
      {feed.connection === "live" && <DegradedBanner degraded={feed.degraded} cisAgeS={cisAgeS} />}
      {signedOut && (
        <p role="alert" data-testid="signed-out" className="m-0 font-semibold text-[var(--us-danger)]">
          {t("ansp.status.signed_out")}{" "}
          <Link href={loginPath(lang)} className="underline">
            {t("ansp.status.sign_in_again")}
          </Link>
        </p>
      )}
    </section>
  );
}
