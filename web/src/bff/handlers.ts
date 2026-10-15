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
//   list; the sign-in operations are not on it, nor the machine intake
//   POST /v1/coordination/notices (the console reads the inbox).
// - logout: the kit's CSRF check and cookie clearing around POST
//   /v1/auth/logout.
// - Idempotency-Key: POST /v1/restrictions requires it and POST
//   /v1/occurrences takes it (the client's reference, api/openapi.yaml
//   IdempotencyKey, OccurrenceIdempotencyKey). The kit's proxy forwards
//   the client's key from uspace-ui 1.0.0 (FORWARDED_REQUEST_HEADERS);
//   the console forwards it only in the contract's shape on those two
//   operations and drops it from every other call. Any other header
//   stays the kit's decision.
//
// - users: the account administration (USER_OPERATIONS) is four exact
//   operations, path and method; another method on one of those paths
//   is 405 without an upstream call. The API decides who (admin only).
//
// - the session ends on the session's own answer only. The kit's
//   `forward` clears both cookies on any upstream 401 (uspace-ui 1.1.1
//   src/auth/server/forward.ts: `if (upstream.status === 401)
//   clearSession(res, opts.session)`). A 401 from GET /v1/auth/me is the
//   session refused and passes as the kit wrote it. A 401 from any other
//   path asks GET /v1/auth/me with the same cookie before the answer
//   leaves: 2xx, the session is live and the kit's cookie clearing is
//   dropped (the 401 itself is passed on unchanged); anything else (401,
//   5xx, no answer) keeps the clearing (fail closed). The BFF still
//   verifies no token: the API decides every request.
// - every summary is api's, the manned picture's count included (api
//   verifies the session and asks manned-feed on the bus): the BFF
//   reaches the API and nothing else.
//
// The WebSockets are not proxied: the browser upgrades /v1/restrictions/
// stream, /v1/coordination/stream and /v1/manned-traffic/stream
// same-origin and the cookie rides the upgrade (M22, docs/PLAN.md section
// 15 row 19). No ticket route.
//
// This file may import only the kit's BFF helpers and next/server
// (eslint-rules/no-server-business-logic.mjs).
import {
  BFF_API_PREFIX,
  bffHandlers,
  forward,
  MIN_CHALLENGE_SECRET_BYTES,
  readSessionToken,
  type BffHandlers,
  type SessionCookieOptions,
} from "@rootxkit/uspace-ui/auth/server";
import { NextRequest, NextResponse } from "next/server";

/** The API's sign-in, its second step and its sign-out (api/openapi.yaml, tag auth). */
export const API_LOGIN_PATH = "/v1/auth/login";
export const API_MFA_PATH = "/v1/auth/mfa";
export const API_LOGOUT_PATH = "/v1/auth/logout";

/** The session's own read (api/openapi.yaml getMe): the one answer whose 401 ends the session. */
export const API_ME_PATH = "/v1/auth/me";

/**
 * The overview's summaries (api/openapi.yaml, one tile each, every one
 * x-process api), each one exact path that the proxy forwards for GET
 * only: another method on one of them is 405 before any upstream call,
 * and a longer or shorter path is not on the list. The API's x-auth
 * decides who reads each.
 */
export const SUMMARY_READS: readonly RegExp[] = [
  /^\/v1\/users\/summary$/,
  /^\/v1\/restriction-requests\/summary$/,
  /^\/v1\/occurrences\/summary$/,
  /^\/v1\/manned-traffic\/summary$/,
];

/**
 * The account administration (api/openapi.yaml tag auth, every one
 * x-auth session:admin): exact path and method, nothing near them. A
 * listed path with another method is 405 before any upstream call; a
 * longer, shorter or other path is not on the list (404). The BFF never
 * reads the role: the API answers anyone but an admin 403. The id is a
 * ULID (components.schemas.ULID).
 */
export const USER_OPERATIONS: readonly { method: string; path: RegExp }[] = [
  { method: "GET", path: /^\/v1\/users$/ },
  { method: "POST", path: /^\/v1\/users$/ },
  { method: "POST", path: /^\/v1\/users\/[0-7][0-9A-HJKMNP-TV-Z]{25}\/reset-mfa$/ },
  { method: "POST", path: /^\/v1\/users\/[0-7][0-9A-HJKMNP-TV-Z]{25}\/disable$/ },
];

/** The methods USER_OPERATIONS lists for a path, or null when the path is not one of them. */
export function userMethodsOf(apiPath: string): string[] | null {
  const methods = USER_OPERATIONS.filter((o) => o.path.test(apiPath)).map((o) => o.method);
  return methods.length === 0 ? null : methods;
}

/**
 * What the proxy may reach: the console's operations and nothing else.
 * /v1/auth/me is the only auth operation on it; login, mfa and logout
 * go through their own routes.
 */
export const PROXY_ALLOW_PATHS: RegExp[] = [
  /^\/v1\/(restrictions|delivery-alarms|adapters|sources)(\/|$)/,
  // The requests: the list, one by its id, and its accept and decline;
  // the summary is on SUMMARY_READS.
  /^\/v1\/restriction-requests(\/[0-9A-HJKMNP-TV-Z]{26}(\/(accept|decline))?)?$/,
  /^\/v1\/coordination\/inbox(\/|$)/,
  /^\/v1\/(occurrences|policy|audit)$/,
  /^\/v1\/outlines\/circle$/,
  /^\/v1\/auth\/me$/,
  ...SUMMARY_READS,
  ...USER_OPERATIONS.map((o) => o.path),
];

/** The header the plan and the occurrence report take, and its shape (api/openapi.yaml IdempotencyKey). */
export const IDEMPOTENCY_HEADER = "Idempotency-Key";
export const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{1,128}$/;

/** The operations the console sends an Idempotency-Key on (method and API path). */
export const IDEMPOTENT_OPERATIONS: readonly { method: string; path: RegExp }[] = [
  { method: "POST", path: /^\/v1\/restrictions$/ },
  { method: "POST", path: /^\/v1\/occurrences$/ },
];

export interface BffConfig {
  /** The API as the web container reaches it (WEB_API_INTERNAL_URL). */
  apiBase: string;
  /** The cookie's Max-Age ceiling, seconds (WEB_SESSION_MAX_AGE_S). */
  sessionMaxAgeS: number;
  /** The upstream timeout of every call, ms (WEB_UPSTREAM_TIMEOUT_MS). */
  timeoutMs: number;
  /**
   * Reverse proxies in front of Next.js that append to X-Forwarded-For
   * (WEB_TRUSTED_PROXY_HOPS, required; 1 behind Caddy). 0 says there is
   * none: the kit's `noTrustedProxy`, and the API gets no client address.
   * From uspace-ui 0.1.0 a secure session never builds without one or
   * the other.
   */
  trustedProxyHops: number;
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

/** The request without its Idempotency-Key, the body passed on unread. */
function withoutIdempotencyKey(req: NextRequest): NextRequest {
  const headers = new Headers(req.headers);
  headers.delete(IDEMPOTENCY_HEADER);
  const init: NonNullable<ConstructorParameters<typeof NextRequest>[1]> & { duplex?: "half" } = { method: req.method, headers };
  if (req.body !== null) {
    init.body = req.body;
    init.duplex = "half";
  }
  return new NextRequest(req.nextUrl, init);
}

/** The kit's option for a hop count: 0 is `noTrustedProxy`. */
function proxyHops(hops: number): { trustedProxyHops: number } | { noTrustedProxy: true } {
  return hops === 0 ? { noTrustedProxy: true } : { trustedProxyHops: hops };
}

/** The largest WEB_TRUSTED_PROXY_HOPS taken (a bound on a malformed value, not a policy). */
export const MAX_TRUSTED_PROXY_HOPS = 8;

/**
 * WEB_TRUSTED_PROXY_HOPS as a whole number 0..MAX_TRUSTED_PROXY_HOPS, or
 * null when it is unset or malformed: never a default, because a wrong
 * count lets a client choose the address the API rate-limits.
 */
export function trustedProxyHopsOf(raw: string | undefined): number | null {
  if (raw === undefined || !/^[0-9]{1,2}$/.test(raw)) return null;
  const n = Number(raw);
  return n <= MAX_TRUSTED_PROXY_HOPS ? n : null;
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
    ...proxyHops(cfg.trustedProxyHops),
    ...(cfg.fetch === undefined ? {} : { fetch: cfg.fetch }),
  });

  // Is the request's session live? GET /v1/auth/me with its cookie,
  // through the kit's forward (its header, redirect and timeout rules; a
  // GET takes no CSRF pair). Only a 2xx says yes.
  const sessionLive = async (req: NextRequest): Promise<boolean> => {
    const headers = new Headers(req.headers);
    for (const h of ["content-length", "content-type", "transfer-encoding", IDEMPOTENCY_HEADER]) headers.delete(h);
    const ask = new NextRequest(new URL(`${BFF_API_PREFIX}${API_ME_PATH}`, req.nextUrl), { method: "GET", headers });
    try {
      const me = await forward(ask, new URL(API_ME_PATH, cfg.apiBase), {
        session,
        allowPaths: [/^\/v1\/auth\/me$/],
        timeoutMs: cfg.timeoutMs,
        ...(cfg.trustedProxyHops > 0 ? { trustedProxyHops: cfg.trustedProxyHops } : {}),
        ...(cfg.fetch === undefined ? {} : { fetch: cfg.fetch }),
      });
      await me.body?.cancel().catch(() => undefined);
      return me.ok;
    } catch {
      return false;
    }
  };

  // The kit's answer; for a 401 of a path other than the session's own
  // read, whose session GET /v1/auth/me still accepts, the same answer
  // without the kit's cookie clearing (the only Set-Cookie on a proxied
  // answer: the kit drops the API's).
  const keepLiveSession = async (req: NextRequest, apiPath: string | null, res: Response): Promise<Response> => {
    if (res.status !== 401 || apiPath === API_ME_PATH || !res.headers.has("set-cookie")) return res;
    // No session cookie: nothing to keep, and nothing to ask about.
    if (readSessionToken(req, session) === null) return res;
    if (!(await sessionLive(req))) return res;
    const headers = new Headers(res.headers);
    headers.delete("set-cookie");
    return new NextResponse(res.body, { status: res.status, statusText: res.statusText, headers });
  };

  // The kit's proxy forwards the client's Idempotency-Key (uspace-ui
  // 1.0.0). The console keeps its narrower rule: a key of the contract's
  // shape on an operation that takes one, and no key anywhere else. A
  // summary is read with GET and nothing else.
  const proxy: Handler = async (req) => {
    const apiPath = req.nextUrl.pathname.startsWith(`${BFF_API_PREFIX}/`) ? req.nextUrl.pathname.slice(BFF_API_PREFIX.length) : null;
    if (apiPath !== null && req.method !== "GET" && SUMMARY_READS.some((p) => p.test(apiPath))) {
      const res = problem(405, "method_not_allowed", "Method not allowed", "a summary is read with GET only");
      res.headers.set("Allow", "GET");
      return res;
    }
    const userMethods = apiPath === null ? null : userMethodsOf(apiPath);
    if (userMethods !== null && !userMethods.includes(req.method)) {
      const res = problem(405, "method_not_allowed", "Method not allowed", `an account operation takes ${userMethods.join(" or ")} only`);
      res.headers.set("Allow", userMethods.join(", "));
      return res;
    }
    const key = req.headers.get(IDEMPOTENCY_HEADER);
    const takesKey = apiPath !== null && IDEMPOTENT_OPERATIONS.some((o) => o.method === req.method && o.path.test(apiPath));
    const res = await kit.proxy(key === null || (takesKey && IDEMPOTENCY_KEY.test(key)) ? req : withoutIdempotencyKey(req));
    return keepLiveSession(req, apiPath, res);
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
 * (fail closed: no sign-in path without the MFA step, and no client
 * address the API rate-limits on taken from a header a client wrote).
 */
export function configProblem(): string | null {
  const apiBase = process.env["WEB_API_INTERNAL_URL"];
  if (apiBase === undefined || apiBase === "") return "WEB_API_INTERNAL_URL is not set";
  const secret = process.env["WEB_MFA_CHALLENGE_SECRET"] ?? "";
  if (new TextEncoder().encode(secret).length < MIN_CHALLENGE_SECRET_BYTES) {
    return `WEB_MFA_CHALLENGE_SECRET is not set or shorter than ${MIN_CHALLENGE_SECRET_BYTES} bytes`;
  }
  if (trustedProxyHopsOf(process.env["WEB_TRUSTED_PROXY_HOPS"]) === null) {
    return `WEB_TRUSTED_PROXY_HOPS is not set or not a whole number 0 to ${MAX_TRUSTED_PROXY_HOPS} (1 behind Caddy, 0 with no proxy)`;
  }
  return null;
}

/** The configuration from the environment, read at the first request. */
export function configFromEnv(): BffConfig | null {
  if (configProblem() !== null) return null;
  const hops = trustedProxyHopsOf(process.env["WEB_TRUSTED_PROXY_HOPS"]);
  if (hops === null) return null;
  return {
    apiBase: process.env["WEB_API_INTERNAL_URL"] ?? "",
    mfaChallengeSecret: process.env["WEB_MFA_CHALLENGE_SECRET"] ?? "",
    // Display-side ceiling only: the API's session lifetime (<= 12 h)
    // shortens it through expires_at.
    sessionMaxAgeS: positiveInt("WEB_SESSION_MAX_AGE_S", 12 * 3600),
    timeoutMs: positiveInt("WEB_UPSTREAM_TIMEOUT_MS", 10_000),
    trustedProxyHops: hops,
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
