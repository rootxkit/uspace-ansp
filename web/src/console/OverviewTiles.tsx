"use client";

// The overview's tiles that read a summary of the API (api/openapi.yaml
// GET .../summary): one bounded read each, counted by the API on its
// database clock, numbers only. A tile is drawn only for the role the
// operation's x-auth admits (a courtesy to the layout: the API answers
// 403 to anyone else). Each is read again every READ_PERIOD_MS; an
// unknown figure is a dash, never a zero, and a read that failed says
// so in the tile (E-02).
import { useEffect } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { StatTile } from "@rootxkit/uspace-ui/ui";
import { RequestIcon, UsersIcon } from "../components/icons";
import { useLoad, type Loaded } from "./context";
import { timesShown } from "./ui";

/** How often a summary is read again. Display-only. */
export const SUMMARY_READ_PERIOD_MS = 10_000;

/** A summary read on mount and every SUMMARY_READ_PERIOD_MS. */
function useSummary<T>(load: Parameters<typeof useLoad<T>>[0], key: string): Loaded<T> {
  const loaded = useLoad(load, key);
  const { reload } = loaded;
  useEffect(() => {
    const id = setInterval(reload, SUMMARY_READ_PERIOD_MS);
    return () => clearInterval(id);
  }, [reload]);
  return loaded;
}

/** The status of a tile whose read failed: the figure is not known. */
function unread(t: ReturnType<typeof useT>, failed: boolean) {
  return failed ? { status: { tone: "warning" as const, label: t("ansp.overview.kpi.unread") } } : {};
}

/** The console accounts (GET /v1/users/summary, admin only). */
export function UsersTile() {
  const t = useT();
  const users = useSummary(async (c) => (await c.GET("/v1/users/summary")).data ?? null, "summary:users");
  const s = users.data;
  return (
    <div data-testid="kpi-users" data-value={s === null ? "" : s.by_status.active}>
      <StatTile
        className="h-full"
        icon={<UsersIcon />}
        label={t("ansp.overview.kpi.users")}
        value={s === null ? null : s.by_status.active}
        {...(s === null
          ? {}
          : {
              hint: t(s.truncated ? "ansp.overview.kpi.users_hint_truncated" : "ansp.overview.kpi.users_hint", {
                disabled: s.by_status.disabled,
                total: s.total,
                admins: s.by_role.admin,
              }),
            })}
        {...unread(t, users.failure !== null)}
      />
    </div>
  );
}

/** The restriction requests awaiting a decision (GET /v1/restriction-requests/summary, watch supervisor). */
export function RequestsTile() {
  const t = useT();
  const { lang } = useLang();
  const requests = useSummary(async (c) => (await c.GET("/v1/restriction-requests/summary")).data ?? null, "summary:requests");
  const s = requests.data;
  const status =
    requests.failure !== null || s === null
      ? unread(t, requests.failure !== null)
      : {
          status:
            s.received > 0
              ? { tone: "warning" as const, label: t("ansp.overview.kpi.requests_waiting") }
              : { tone: "ok" as const, label: t("ansp.overview.kpi.requests_none") },
        };
  return (
    <div data-testid="kpi-requests" data-value={s === null ? "" : s.received}>
      <StatTile
        className="h-full"
        icon={<RequestIcon />}
        label={t("ansp.overview.kpi.requests")}
        value={s === null ? null : s.truncated ? t("ansp.overview.kpi.at_least", { count: s.received }) : s.received}
        {...(s === null || s.oldest_received_at === null
          ? {}
          : { hint: t("ansp.overview.kpi.requests_oldest", timesShown({ since: s.oldest_received_at }, lang)) })}
        {...status}
      />
    </div>
  );
}
