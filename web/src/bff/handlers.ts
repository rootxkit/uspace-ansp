// The three BFF routes (/_bff/login, /_bff/logout, /_bff/api/*) on the
// kit's helpers (spec 00 §6.2, M21, M22; docs/PLAN.md D9). Nothing else
// runs on the server: no database, no bus, no key, no judgement. The BFF
// never verifies a token; the API decides every request.
//
// - login: the kit's `login`. The first request {username, password}
//   becomes POST /v1/auth/login, whose answer is an MFA challenge
//   {mfa_token, expires_at, enrolment?} (MFA is mandatory for every role,
//   01 §4); the kit seals the challenge into the `uspace_mfa` cookie
//   (HttpOnly, Path=/_bff) under WEB_MFA_CHALLENGE_SECRET and answers
//   {status: mfa_required, enrolment?}. The second request {username,
//   otp} becomes POST /v1/auth/mfa {mfa_token, code}; its session sets
//   `uspace_session` (HttpOnly, Secure, SameSite=Strict) and the
//   `uspace_csrf` double-submit cookie. The two sign-in steps are one
//   route: the kit has no separate MFA route to mount.
// - proxy: the kit's `proxy`, forwarding /_bff/api/v1/<console paths>
//   with the session cookie as the bearer; unsafe methods need
//   X-CSRF-Token equal to the CSRF cookie. PROXY_ALLOW_PATHS is the whole
//   list; the sign-in operations are not on it.
// - logout: the kit's CSRF check and cookie clearing around POST
//   /v1/auth/logout.
// - Idempotency-Key: POST /v1/restrictions requires it (the client's
//   reference, api/openapi.yaml IdempotencyKey), and the kit's forward
//   passes only its fixed header list (FORWARDED_REQUEST_HEADERS of
//   uspace-ui 0.1.0-rc.1), so a key of the contract's shape is added to
//   that one call here, through the kit's own forward and its checks.
//   Nothing else is added; any other header stays the kit's decision.
//
// The WebSocket is not proxied: the browser upgrades /v1/restrictions/
// stream same-origin and the cookie rides the upgrade (M22, docs/PLAN.md
// section 15 row 19). No ticket route.
//
// This file may import only the kit's BFF helpers and next/server
// (eslint-rules/no-server-business-logic.mjs).
import {
  BFF_API_PREFIX,
  bffHandlers,
  forward,
  MIN_CHALLENGE_SECRET_BYTES,
  type BffHandlers,
  type SessionCookieOptions,
} from "@rootxkit/uspace-ui/auth/server";
import { NextResponse, type NextRequest } from "next/server";

/** The API's sign-in, its second step and its sign-out (api/openapi.yaml, tag auth). */
export const API_LOGIN_PATH = "/v1/auth/login";
export const API_MFA_PATH = "/v1/auth/mfa";
export const API_LOGOUT_PATH = "/v1/auth/logout";

/**
 * What the proxy may reach: the console's operations and nothing else.
 * /v1/auth/me is the only auth operation on it; login, mfa and logout
 * go through their own routes.
 */
export const PROXY_ALLOW_PATHS: RegExp[] = [
  /^\/v1\/(restrictions|restriction-requests|delivery-alarms|adapters|sources)(\/|$)/,
  /^\/v1\/auth\/me$/,
];

/** The header the plan operation requires, and its shape (api/openapi.yaml IdempotencyKey). */
export const IDEMPOTENCY_HEADER = "Idempotency-Key";
export const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{1,128}$/;

/** The operations the console sends an Idempotency-Key on (method and API path). */
export const IDEMPOTENT_OPERATIONS: readonly { method: string; path: RegExp }[] = [{ method: "POST", path: /^\/v1\/restrictions$/ }];

export interface BffConfig {
  /** The API as the web container reaches it (WEB_API_INTERNAL_URL). */
  apiBase: string;
  /** The cookie's Max-Age ceiling, seconds (WEB_SESSION_MAX_AGE_S). */
  sessionMaxAgeS: number;
  /** The upstream timeout of every call, ms (WEB_UPSTREAM_TIMEOUT_MS). */
  timeoutMs: number;
  /** Reverse proxies in front of Next.js (WEB_TRUSTED_PROXY_HOPS). */
  trustedProxyHops?: number;
  /**
   * Seals the MFA challenge cookie between the two sign-in steps
   * (WEB_MFA_CHALLENGE_SECRET, at least 32 bytes; a secret, never in the
   * repository).
   */
  mfaChallengeSecret: string;
  fetch?: typeof fetch;
}

export type Handler = (req: NextRequest) => Promise<Response>;

export interface Bff {
  login: Handler;
  logout: Handler;
  proxy: Handler;
}

function problem(status: number, slug: string, title: string, detail: string): NextResponse {
  return NextResponse.json(
    { type: `https://schemas.uspace.ge/problems/${slug}`, title, status, detail, errors: [] },
    {
      status,
      headers: { "Content-Type": "application/problem+json", "Cache-Control": "no-store" },
    },
  );
}

/** The three handlers for one configuration. */
export function createBff(cfg: BffConfig): Bff {
  const session: SessionCookieOptions = { secure: true, maxAgeS: cfg.sessionMaxAgeS };
  const kit: BffHandlers = bffHandlers({
    apiBase: cfg.apiBase,
    apiLoginPath: API_LOGIN_PATH,
    apiMfaPath: API_MFA_PATH,
    apiLogoutPath: API_LOGOUT_PATH,
    mfaChallengeSecret: cfg.mfaChallengeSecret,
    session,
    allowPaths: PROXY_ALLOW_PATHS,
    timeoutMs: cfg.timeoutMs,
    ...(cfg.trustedProxyHops === undefined ? {} : { trustedProxyHops: cfg.trustedProxyHops }),
    ...(cfg.fetch === undefined ? {} : { fetch: cfg.fetch }),
  });
  const base = new URL(cfg.apiBase);
  const baseFetch = cfg.fetch ?? fetch;

  // The kit's proxy, but for a call that carries an Idempotency-Key of
  // the contract's shape on an operation that takes one: the same target,
  // forwarded by the kit with the key added to the upstream request.
  const proxy: Handler = (req) => {
    const key = req.headers.get(IDEMPOTENCY_HEADER);
    const apiPath = req.nextUrl.pathname.startsWith(`${BFF_API_PREFIX}/`) ? req.nextUrl.pathname.slice(BFF_API_PREFIX.length) : null;
    const takesKey = apiPath !== null && IDEMPOTENT_OPERATIONS.some((o) => o.method === req.method && o.path.test(apiPath));
    if (key === null || !IDEMPOTENCY_KEY.test(key) || !takesKey || apiPath === null) return kit.proxy(req);
    const target = new URL(base.pathname.replace(/\/$/, "") + apiPath, base);
    target.search = req.nextUrl.search;
    const withKey: typeof fetch = (input, init) => {
      const headers = new Headers(init?.headers);
      headers.set(IDEMPOTENCY_HEADER, key);
      return baseFetch(input, { ...init, headers });
    };
    return forward(req, target, {
      session,
      allowPaths: PROXY_ALLOW_PATHS,
      timeoutMs: cfg.timeoutMs,
      fetch: withKey,
      ...(cfg.trustedProxyHops === undefined ? {} : { trustedProxyHops: cfg.trustedProxyHops }),
    });
  };
  return { login: kit.login, logout: kit.logout, proxy };
}

function positiveInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) throw new Error(`${name}: want a whole number of at least 1, got ${JSON.stringify(raw)}`);
  return n;
}

/**
 * What the environment lacks for the BFF, naming the variable, or null
 * when it is complete. Without it every BFF route answers 503 naming it
 * (fail closed: no sign-in path without the MFA step).
 */
export function configProblem(): string | null {
  const apiBase = process.env["WEB_API_INTERNAL_URL"];
  if (apiBase === undefined || apiBase === "") return "WEB_API_INTERNAL_URL is not set";
  const secret = process.env["WEB_MFA_CHALLENGE_SECRET"] ?? "";
  if (new TextEncoder().encode(secret).length < MIN_CHALLENGE_SECRET_BYTES) {
    return `WEB_MFA_CHALLENGE_SECRET is not set or shorter than ${MIN_CHALLENGE_SECRET_BYTES} bytes`;
  }
  return null;
}

/** The configuration from the environment, read at the first request. */
export function configFromEnv(): BffConfig | null {
  if (configProblem() !== null) return null;
  const hops = process.env["WEB_TRUSTED_PROXY_HOPS"];
  return {
    apiBase: process.env["WEB_API_INTERNAL_URL"] ?? "",
    mfaChallengeSecret: process.env["WEB_MFA_CHALLENGE_SECRET"] ?? "",
    // Display-side ceiling only: the API's session lifetime (<= 12 h)
    // shortens it through expires_at.
    sessionMaxAgeS: positiveInt("WEB_SESSION_MAX_AGE_S", 12 * 3600),
    timeoutMs: positiveInt("WEB_UPSTREAM_TIMEOUT_MS", 10_000),
    ...(hops === undefined || hops === "" ? {} : { trustedProxyHops: positiveInt("WEB_TRUSTED_PROXY_HOPS", 1) }),
  };
}

let cached: Bff | null = null;

function unconfigured(detail: string): Handler {
  return () => Promise.resolve(problem(503, "bff_unavailable", "Console unavailable", detail));
}

/** The handlers for this process, built lazily (the build has no environment). */
export function bff(): Bff {
  if (cached !== null) return cached;
  const missing = configProblem();
  const cfg = configFromEnv();
  if (missing !== null || cfg === null) {
    const off = unconfigured(missing ?? "the BFF is not configured");
    return { login: off, logout: off, proxy: off };
  }
  cached = createBff(cfg);
  return cached;
}
