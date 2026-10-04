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

export interface NavItem {
  /** The path under /<locale>. */
  path: string;
  /** The catalogue key of its label. */
  labelKey: string;
  /** Linked for an admin only: every operation of the page is admin's (a courtesy; the API answers 403 to anyone else). */
  adminOnly?: true;
}

/** Every page, in navigation order. */
export const NAV_ITEMS: readonly NavItem[] = [
  { path: "/restrictions", labelKey: "ansp.nav.restrictions" },
  { path: "/restrictions/new", labelKey: "ansp.nav.plan" },
  { path: "/picture", labelKey: "ansp.nav.picture" },
  { path: "/inbox", labelKey: "ansp.nav.inbox" },
  { path: "/requests", labelKey: "ansp.nav.requests" },
  { path: "/adapters", labelKey: "ansp.nav.adapters" },
];

/** The navigation a role is shown. */
export function navFor(role: ConsoleRole | null): NavItem[] {
  return NAV_ITEMS.filter((i) => i.adminOnly !== true || mayAdminister(role));
}
