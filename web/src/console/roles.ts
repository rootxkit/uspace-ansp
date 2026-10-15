// The console roles (01 §4, api/openapi.yaml ConsoleRole) and what each one is
// shown. A courtesy to the layout, never a control: a button hidden here
// is still refused by the API (each operation's x-auth), and a page
// reached by its address shows the API's 403.
import type { components } from "../api/types";

export type ConsoleRole = components["schemas"]["Role"];

export const ROLES: readonly ConsoleRole[] = ["watch_supervisor", "viewer", "admin"];

export function isRole(v: unknown): v is ConsoleRole {
  return typeof v === "string" && (ROLES as readonly string[]).includes(v);
}

/**
 * The acts on restrictions, requests and alarms are x-auth
 * session:watch_supervisor in api/openapi.yaml: that role alone, an
 * admin included out.
 */
export function maySupervise(role: ConsoleRole | null): boolean {
  return role === "watch_supervisor";
}

/**
 * The source switches, the policy and the audit log are x-auth
 * session:admin in api/openapi.yaml (GET /v1/sources is any session).
 */
export function mayAdminister(role: ConsoleRole | null): boolean {
  return role === "admin";
}

/** The sidebar's groups, in order (a courtesy to the layout, like the items). */
export const NAV_GROUPS = ["monitoring", "airspace", "coordination", "surveillance", "administration"] as const;
export type NavGroupId = (typeof NAV_GROUPS)[number];

export interface NavItem {
  /** The path under /<locale>. */
  path: string;
  /** The catalogue key of its label. */
  labelKey: string;
  /** The sidebar group it is listed under. */
  group: NavGroupId;
  /** Linked for an admin only: every operation of the page is admin's (a courtesy; the API answers 403 to anyone else). */
  adminOnly?: true;
}

/** Every page, in navigation order. */
export const NAV_ITEMS: readonly NavItem[] = [
  { path: "/overview", labelKey: "ansp.nav.overview", group: "monitoring" },
  { path: "/picture", labelKey: "ansp.nav.picture", group: "monitoring" },
  { path: "/restrictions", labelKey: "ansp.nav.restrictions", group: "airspace" },
  { path: "/restrictions/new", labelKey: "ansp.nav.plan", group: "airspace" },
  { path: "/requests", labelKey: "ansp.nav.requests", group: "airspace" },
  { path: "/inbox", labelKey: "ansp.nav.inbox", group: "coordination" },
  { path: "/occurrences/new", labelKey: "ansp.nav.occurrence", group: "coordination" },
  { path: "/adapters", labelKey: "ansp.nav.adapters", group: "surveillance" },
  { path: "/sources", labelKey: "ansp.nav.sources", group: "surveillance" },
  { path: "/policy", labelKey: "ansp.nav.policy", group: "administration", adminOnly: true },
  { path: "/audit", labelKey: "ansp.nav.audit", group: "administration", adminOnly: true },
  { path: "/users", labelKey: "ansp.nav.users", group: "administration", adminOnly: true },
];

/** The navigation a role is shown. */
export function navFor(role: ConsoleRole | null): NavItem[] {
  return NAV_ITEMS.filter((i) => i.adminOnly !== true || mayAdminister(role));
}

/**
 * The item a path under /<locale> belongs to: the one whose path is the
 * longest prefix of it on a segment boundary, so a restriction's own page
 * is under "Restrictions" and the editor under "Plan a restriction".
 */
export function navItemOf(path: string): NavItem | null {
  let best: NavItem | null = null;
  for (const i of NAV_ITEMS) {
    if (path !== i.path && !path.startsWith(`${i.path}/`)) continue;
    if (best === null || i.path.length > best.path.length) best = i;
  }
  return best;
}
