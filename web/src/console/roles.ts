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

export interface NavItem {
  /** The path under /<locale>. */
  path: string;
  /** The catalogue key of its label. */
  labelKey: string;
}

/** Every page, in navigation order; every one is readable by any session. */
export const NAV_ITEMS: readonly NavItem[] = [
  { path: "/restrictions", labelKey: "ansp.nav.restrictions" },
  { path: "/restrictions/new", labelKey: "ansp.nav.plan" },
  { path: "/requests", labelKey: "ansp.nav.requests" },
  { path: "/adapters", labelKey: "ansp.nav.adapters" },
];
