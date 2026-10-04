"use client";

// The signed-in console's frame: the status bar first, then the
// navigation, the account (role and sign-out), a line that says what the
// console can and cannot do, and the page. Every page is readable by any
// role; the acts are a watch supervisor's (the API decides).
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";
import { SessionProvider, useSession } from "@rootxkit/uspace-ui/auth/client";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import type { SessionDisplay } from "@rootxkit/uspace-ui/model";
import { Button } from "@rootxkit/uspace-ui/ui";
import { ConsoleProvider, loginPath, useConsole } from "./context";
import { navFor } from "./roles";
import { StatusBar } from "./StatusBar";
import { Loading, ProblemNotice } from "./ui";

function Account() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const { me } = useConsole();
  const { session, signOut } = useSession();
  const [failed, setFailed] = useState(false);
  const role = me?.role ?? session?.roles[0] ?? null;
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm">
      {me !== null && (
        <span data-testid="account">
          {t("ansp.account.who", { username: me.username, role: role === null ? "—" : t(`ansp.role.${role}`) })}
        </span>
      )}
      <Button
        type="button"
        variant="outline"
        size="sm"
        data-testid="sign-out"
        onClick={() => {
          setFailed(false);
          signOut()
            .then(() => router.replace(loginPath(lang)))
            .catch(() => setFailed(true));
        }}
      >
        {t("ansp.account.sign_out")}
      </Button>
      {failed && (
        <span role="alert" className="text-xs text-[var(--us-danger)]">
          {t("ansp.account.sign_out_failed")}
        </span>
      )}
    </div>
  );
}

function Frame({ children }: { children: ReactNode }) {
  const t = useT();
  const { lang } = useLang();
  const pathname = usePathname();
  const { me, role, meFailure, signedOut } = useConsole();
  return (
    <div className="flex flex-col">
      <StatusBar />
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--us-border)] px-4 py-2">
        <nav aria-label={t("ansp.nav.label")} className="flex flex-wrap gap-3 text-sm">
          {navFor(role).map((i) => {
            const href = `/${lang}${i.path}`;
            const current = pathname === href;
            return (
              <Link
                key={i.path}
                href={href}
                aria-current={current ? "page" : undefined}
                className={current ? "font-bold underline underline-offset-4" : "underline-offset-4 hover:underline"}
              >
                {t(i.labelKey)}
              </Link>
            );
          })}
        </nav>
        <Account />
      </div>
      <p className="m-0 border-b border-[var(--us-border)] px-4 py-1 text-xs text-[var(--us-text-muted)]">{t("ansp.scope_notice")}</p>
      <div className="flex flex-col gap-4 p-4">
        {meFailure !== null && <ProblemNotice failure={meFailure} />}
        {me === null && meFailure === null && !signedOut ? <Loading /> : children}
      </div>
    </div>
  );
}

/**
 * The signed-in console around a page. `session` is the cookie's claims,
 * decoded on the server without verification (display only: which role
 * to name before /me answers); the API decides every request.
 */
export function ConsoleShell({ session, children }: { session: SessionDisplay | null; children: ReactNode }) {
  return (
    <SessionProvider session={session}>
      <ConsoleProvider>
        <Frame>{children}</Frame>
      </ConsoleProvider>
    </SessionProvider>
  );
}
