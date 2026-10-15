"use client";

// The signed-in console's frame: the kit's AppShell with the sidebar's
// navigation groups (the current page marked), the top bar with the
// restriction stream's pill, the scheme toggle, the language switch and
// the account menu (role and sign-out); then, on every page, the status
// bar where the supervisor looks first, the page, and the footer that
// says what the console can and cannot do. Every page is readable by any
// role; the acts are a watch supervisor's (the API decides).
import { usePathname, useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";
import { SessionProvider, useSession } from "@rootxkit/uspace-ui/auth/client";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import type { SessionDisplay } from "@rootxkit/uspace-ui/model";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { AppShell, DropdownMenuItem, StatusBadge, StatusPill, UserMenu, type NavGroup } from "@rootxkit/uspace-ui/ui";
import { BrandMark, FrameFooter, SchemeToggle } from "../components/frame";
import {
  AdapterIcon,
  AuditIcon,
  InboxIcon,
  OccurrenceIcon,
  OverviewIcon,
  PictureIcon,
  PlanIcon,
  PolicyIcon,
  RequestIcon,
  RestrictionIcon,
  SignOutIcon,
  SwitchIcon,
  UsersIcon,
} from "../components/icons";
import { ConsoleProvider, loginPath, useConsole } from "./context";
import { awaitingCount } from "./inbox";
import { InboxProvider, useInbox } from "./InboxProvider";
import { NAV_GROUPS, navFor, navItemOf } from "./roles";
import { StatusBar } from "./StatusBar";
import { Loading, ProblemNotice, renderLink } from "./ui";

/** Each page's icon in the sidebar. Decorative: the label is beside it. */
const NAV_ICON: Readonly<Record<string, ReactNode>> = {
  "/overview": <OverviewIcon />,
  "/picture": <PictureIcon />,
  "/restrictions": <RestrictionIcon />,
  "/restrictions/new": <PlanIcon />,
  "/requests": <RequestIcon />,
  "/inbox": <InboxIcon />,
  "/occurrences/new": <OccurrenceIcon />,
  "/adapters": <AdapterIcon />,
  "/sources": <SwitchIcon />,
  "/policy": <PolicyIcon />,
  "/audit": <AuditIcon />,
  "/users": <UsersIcon />,
};

/** The notices awaiting a person, beside the inbox's name: escalated ones loudest. */
function InboxBadge() {
  const t = useT();
  const inbox = useInbox();
  const waiting = awaitingCount(inbox.notices.values());
  const total = waiting.escalated + waiting.awaiting;
  if (total === 0) return null;
  return (
    <StatusBadge tone={waiting.escalated > 0 ? "critical" : "warning"} data-testid="nav-inbox-badge">
      <span aria-hidden="true">{total}</span>
      <span className="sr-only">{t("ansp.nav.awaiting", { count: total })}</span>
    </StatusBadge>
  );
}

function Account() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const { me } = useConsole();
  const { session, signOut } = useSession();
  const [failed, setFailed] = useState(false);
  const role = me?.role ?? session?.roles[0] ?? null;
  const name = me?.username ?? session?.sub ?? null;
  if (name === null) return null;
  return (
    <span className="flex items-center gap-2">
      {failed && (
        <span role="alert" className="text-xs font-semibold text-status-critical">
          {t("ansp.account.sign_out_failed")}
        </span>
      )}
      <UserMenu name={name} {...(role === null ? {} : { detail: t(`ansp.role.${role}`) })}>
        <DropdownMenuItem
          data-testid="sign-out"
          onSelect={() => {
            setFailed(false);
            signOut()
              .then(() => router.replace(loginPath(lang)))
              .catch(() => setFailed(true));
          }}
        >
          <SignOutIcon />
          {t("ansp.account.sign_out")}
        </DropdownMenuItem>
      </UserMenu>
    </span>
  );
}

/** Who is signed in, as /me says, under the navigation. */
function SidebarAccount() {
  const t = useT();
  const { me } = useConsole();
  if (me === null) return null;
  return (
    <p className="m-0 flex flex-col gap-0.5">
      <span>{t("ansp.account.signed_in")}</span>
      <span data-testid="account" className="font-semibold text-sidebar-text">
        {t("ansp.account.who", { username: me.username, role: t(`ansp.role.${me.role}`) })}
      </span>
    </p>
  );
}

function Frame({ children }: { children: ReactNode }) {
  const t = useT();
  const { lang } = useLang();
  const { brand } = useTheme();
  const pathname = usePathname();
  const { me, role, meFailure, signedOut, feed } = useConsole();
  const current = navItemOf(pathname.replace(/^\/(ka|en)(?=\/|$)/, ""));
  const items = navFor(role);
  const nav: NavGroup[] = NAV_GROUPS.map((g) => ({
    id: g,
    label: t(`ansp.nav.group.${g}`),
    items: items
      .filter((i) => i.group === g)
      .map((i) => ({
        id: i.path,
        label: t(i.labelKey),
        href: `/${lang}${i.path}`,
        icon: NAV_ICON[i.path],
        active: current?.path === i.path,
        ...(i.path === "/inbox" ? { badge: <InboxBadge /> } : {}),
      })),
  })).filter((g) => g.items.length > 0);

  return (
    <AppShell
      systemName={brand.name}
      logo={<BrandMark />}
      nav={nav}
      renderLink={renderLink}
      status={<StatusPill state={feed.connection} />}
      actions={<SchemeToggle />}
      user={<Account />}
      sidebarFooter={<SidebarAccount />}
    >
      <div className="mx-auto flex w-full max-w-[112rem] flex-col gap-5 p-4 sm:p-6">
        <StatusBar />
        {meFailure !== null && <ProblemNotice failure={meFailure} />}
        {me === null && meFailure === null && !signedOut ? <Loading /> : children}
        <FrameFooter scope />
      </div>
    </AppShell>
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
        <InboxProvider>
          <Frame>{children}</Frame>
        </InboxProvider>
      </ConsoleProvider>
    </SessionProvider>
  );
}
