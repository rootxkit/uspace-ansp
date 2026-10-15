"use client";

// The status bar, where the supervisor looks first (CLAUDE.md rule 4,
// M29): the restriction stream's state from its console/status/v1 frames
// (live, connecting, down since T), what the server says is degraded, the
// CIS version and the age of its projection, and the API's NATS state.
// A 4401 close or a 401 answer is "signed out, sign in again" with the
// way back; nothing here is a verdict of its own. Below it, on every
// page, the coordination stream's state and the notices awaiting a
// person: escalated ones loudest, with the way to the inbox.
import Link from "next/link";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { useNowMs } from "@rootxkit/uspace-ui/live";
import { DegradedBanner, FeedStatusBar } from "@rootxkit/uspace-ui/status";
import { loginPath, useConsole } from "./context";
import { awaitingCount } from "./inbox";
import { useInbox } from "./InboxProvider";
import { timesShown } from "./ui";

/** How often ages on the bar are redrawn. Display-only. */
const TICK_MS = 1000;

export function StatusBar() {
  const t = useT();
  const { lang } = useLang();
  const { feed, signedOut } = useConsole();
  const inbox = useInbox();
  const nowMs = useNowMs(TICK_MS);
  const waiting = awaitingCount(inbox.notices.values());
  const coord = inbox.feed.connection;
  const { cisVersion, cisAgeS, nats } = feed.extras;
  return (
    <section
      aria-label={t("ansp.status.label")}
      data-testid="status-bar"
      data-connection={feed.connection}
      className="flex flex-col gap-2 rounded-lg border border-border bg-card px-4 py-2.5 text-xs shadow-panel"
    >
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1">
        <FeedStatusBar status={feed} nowMs={nowMs} />
        {feed.connection === "live" && (
          <span data-testid="cis-status" className="text-muted-foreground">
            {cisVersion === null
              ? t("ansp.status.cis_none")
              : t("ansp.status.cis", { version: cisVersion, age: cisAgeS === null ? "—" : Math.round(cisAgeS) })}
          </span>
        )}
        {feed.connection === "live" && nats !== null && <span className="text-muted-foreground">{t("ansp.status.nats", { state: nats })}</span>}
        <span
          className={`ms-auto ${coord === "live" ? "text-muted-foreground" : "font-semibold text-status-critical"}`}
          data-testid="coordination-status"
          data-connection={coord}
        >
          {t(`ansp.status.coordination.${coord}`, timesShown({ since: new Date(inbox.feed.sinceMs).toISOString() }, lang))}
        </span>
      </div>
      {feed.connection === "live" && <DegradedBanner degraded={feed.degraded} cisAgeS={cisAgeS} />}
      {waiting.escalated > 0 && (
        <p
          role="alert"
          data-testid="escalated-banner"
          className="m-0 rounded-md border border-status-critical-border bg-status-critical-soft px-3 py-2 text-sm font-bold text-status-critical"
        >
          {t("ansp.status.escalated", { count: waiting.escalated })}{" "}
          <Link href={`/${lang}/inbox`} className="underline">
            {t("ansp.status.open_inbox")}
          </Link>
        </p>
      )}
      {waiting.escalated === 0 && waiting.awaiting > 0 && (
        <p data-testid="awaiting-banner" className="m-0 rounded-md border border-status-warning-border bg-status-warning-soft px-3 py-2 text-sm font-semibold text-status-warning">
          {t("ansp.status.awaiting", { count: waiting.awaiting })}{" "}
          <Link href={`/${lang}/inbox`} className="underline">
            {t("ansp.status.open_inbox")}
          </Link>
        </p>
      )}
      {signedOut && (
        <p
          role="alert"
          data-testid="signed-out"
          className="m-0 rounded-md border border-status-critical-border bg-status-critical-soft px-3 py-2 text-sm font-semibold text-status-critical"
        >
          {t("ansp.status.signed_out")}{" "}
          <Link href={loginPath(lang)} className="underline">
            {t("ansp.status.sign_in_again")}
          </Link>
        </p>
      )}
    </section>
  );
}
