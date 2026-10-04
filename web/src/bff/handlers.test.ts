// The BFF's three routes against a mocked API (fetch). Each refusal has
// its acceptance twin that differs in one thing (E-01).
import { readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { NextRequest } from "next/server";
import { describe, expect, it, vi } from "vitest";
import { configFromEnv, configProblem, createBff, type BffConfig } from "./handlers";

const ORIGIN = "https://ansp.test";
const API = "http://api.internal:8080";
// A test value built at run time, not a secret.
const MFA_SECRET = "t".repeat(32);

interface Call {
  url: string;
  method: string;
  headers: Headers;
  body: string | null;
}

function mockApi(answer: (c: Call) => Response) {
  const calls: Call[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    const call: Call = {
      url: req.url,
      method: req.method,
      headers: req.headers,
      body: req.body === null ? null : await req.text(),
    };
    calls.push(call);
    return answer(call);
  });
  return { calls, fetch: fetchMock as unknown as typeof fetch };
}

function bffWith(f: typeof fetch) {
  const cfg: BffConfig = { apiBase: API, sessionMaxAgeS: 43200, timeoutMs: 2000, mfaChallengeSecret: MFA_SECRET, fetch: f };
  return createBff(cfg);
}

function req(pathname: string, init: { method: string; headers?: Record<string, string>; body?: string }) {
  return new NextRequest(`${ORIGIN}${pathname}`, {
    method: init.method,
    headers: { host: "ansp.test", ...init.headers },
    ...(init.body === undefined ? {} : { body: init.body }),
  });
}

/** The Set-Cookie lines of a response, by cookie name. */
function setCookies(res: Response): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of res.headers.getSetCookie()) {
    const name = line.slice(0, line.indexOf("="));
    out.set(name, line);
  }
  return out;
}

// The SessionResponse of POST /v1/auth/mfa (api/openapi.yaml).
const SESSION = {
  token: "header.payload.signature",
  token_type: "Bearer",
  expires_at: new Date(Date.now() + 3600_000).toISOString(),
  idle_timeout_s: 1800,
  user: { id: "u1", username: "super1", role: "watch_supervisor", status: "active", created_at: "2026-10-01T08:00:00.000Z", last_login_at: null },
};

// The LoginChallenge of POST /v1/auth/login.
const CHALLENGE = { mfa_token: "challenge-token-abc", expires_at: new Date(Date.now() + 300_000).toISOString() };

describe("login", () => {
  const login = (headers: Record<string, string> = {}) =>
    req("/_bff/login", {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", ...headers },
      body: JSON.stringify({ username: "super1", password: "pw" }),
    });

  it("posts the credentials to POST /v1/auth/login and answers the challenge without a session", async () => {
    const api = mockApi(() => Response.json(CHALLENGE, { status: 200 }));
    const res = await bffWith(api.fetch).login(login());
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "mfa_required" });
    expect(api.calls).toHaveLength(1);
    expect(api.calls[0]?.method).toBe("POST");
    expect(api.calls[0]?.url).toBe(`${API}/v1/auth/login`);
    expect(JSON.parse(api.calls[0]?.body ?? "{}")).toEqual({ username: "super1", password: "pw" });
    expect(setCookies(res).has("uspace_session")).toBe(false);
  });

  it("hands the first sign-in's enrolment (secret and otpauth URI) to the page", async () => {
    const enrolment = { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/ANSP:super1?secret=JBSWY3DPEHPK3PXP" };
    const api = mockApi(() => Response.json({ ...CHALLENGE, enrolment }, { status: 200 }));
    const res = await bffWith(api.fetch).login(login());
    expect(await res.json()).toEqual({
      status: "mfa_required",
      enrolment: { secret: enrolment.secret, otpauthUri: enrolment.otpauth_uri },
    });
  });

  it("passes the API's refusal through and sets no cookie", async () => {
    const api = mockApi(() =>
      Response.json(
        { type: "https://schemas.uspace.ge/problems/invalid_credentials", title: "Invalid credentials", status: 401 },
        { status: 401, headers: { "content-type": "application/problem+json" } },
      ),
    );
    const res = await bffWith(api.fetch).login(login());
    expect(res.status).toBe(401);
    expect(setCookies(res).size).toBe(0);
  });

  it("refuses a cross-origin sign-in before calling the API", async () => {
    const api = mockApi(() => Response.json(CHALLENGE, { status: 200 }));
    const res = await bffWith(api.fetch).login(login({ origin: "https://evil.test" }));
    expect(res.status).toBe(403);
    expect(api.calls).toHaveLength(0);
  });
});

describe("two-step sign-in (MFA)", () => {
  const step = (body: Record<string, string>, cookie?: string) =>
    req("/_bff/login", {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", ...(cookie === undefined ? {} : { cookie }) },
      body: JSON.stringify(body),
    });
  /** The `name=value` of a Set-Cookie line, for the next request. */
  const pair = (line: string | undefined) => (line ?? "").split(";")[0] ?? "";

  it("seals the API's challenge into uspace_mfa and exchanges it with the code at POST /v1/auth/mfa", async () => {
    const api = mockApi((c) =>
      c.url.endsWith("/v1/auth/mfa") ? Response.json(SESSION, { status: 200 }) : Response.json(CHALLENGE, { status: 200 }),
    );
    const bff = bffWith(api.fetch);
    const first = await bff.login(step({ username: "super1", password: "pw" }));
    expect(first.status).toBe(200);
    expect(await first.json()).toEqual({ status: "mfa_required" });
    const mfa = setCookies(first).get("uspace_mfa") ?? "";
    expect(mfa).toMatch(/HttpOnly/i);
    expect(mfa).toMatch(/Path=\/_bff/i);
    expect(mfa).toMatch(/SameSite=Strict/i);
    // Sealed: the challenge itself is not in the cookie, nor a session.
    expect(mfa).not.toContain(CHALLENGE.mfa_token);
    expect(setCookies(first).has("uspace_session")).toBe(false);
    expect(api.calls[0]?.url).toBe(`${API}/v1/auth/login`);

    const second = await bff.login(step({ username: "super1", otp: "123456" }, pair(mfa)));
    expect(second.status).toBe(200);
    expect(api.calls).toHaveLength(2);
    expect(api.calls[1]?.method).toBe("POST");
    expect(api.calls[1]?.url).toBe(`${API}/v1/auth/mfa`);
    expect(JSON.parse(api.calls[1]?.body ?? "{}")).toEqual({ mfa_token: CHALLENGE.mfa_token, code: "123456" });
    const cookies = setCookies(second);
    expect(cookies.get("uspace_session") ?? "").toContain(`uspace_session=${SESSION.token}`);
    const session = cookies.get("uspace_session") ?? "";
    expect(session).toMatch(/HttpOnly/i);
    expect(session).toMatch(/Secure/i);
    expect(session).toMatch(/SameSite=Strict/i);
    const csrf = cookies.get("uspace_csrf") ?? "";
    expect(csrf).toMatch(/^uspace_csrf=[A-Za-z0-9_-]{20,};/);
    expect(csrf).not.toMatch(/HttpOnly/i);
    expect(csrf).toMatch(/SameSite=Strict/i);
    expect(cookies.get("uspace_mfa") ?? "").toMatch(/Max-Age=0/i);
    // The token never reaches page script.
    expect(await second.text()).not.toContain(SESSION.token);
  });

  it("passes a wrong code's 401 through and keeps the challenge cookie", async () => {
    const api = mockApi((c) =>
      c.url.endsWith("/v1/auth/mfa")
        ? Response.json(
            { type: "https://schemas.uspace.ge/problems/invalid_totp", title: "Unauthorized", status: 401 },
            { status: 401, headers: { "content-type": "application/problem+json" } },
          )
        : Response.json(CHALLENGE, { status: 200 }),
    );
    const bff = bffWith(api.fetch);
    const first = await bff.login(step({ username: "super1", password: "pw" }));
    const res = await bff.login(step({ username: "super1", otp: "000000" }, pair(setCookies(first).get("uspace_mfa"))));
    expect(res.status).toBe(401);
    expect(setCookies(res).size).toBe(0);
  });

  it("refuses the code step without the password step's cookie, before calling the API", async () => {
    const api = mockApi(() => Response.json(SESSION, { status: 201 }));
    const res = await bffWith(api.fetch).login(step({ username: "super1", otp: "123456" }));
    expect(res.status).toBe(401);
    expect(api.calls).toHaveLength(0);
  });
});

describe("configuration", () => {
  const keys = ["WEB_API_INTERNAL_URL", "WEB_MFA_CHALLENGE_SECRET"] as const;
  function withEnv(env: Partial<Record<(typeof keys)[number], string>>, run: () => void) {
    try {
      for (const k of keys) vi.stubEnv(k, env[k]);
      run();
    } finally {
      vi.unstubAllEnvs();
    }
  }

  it("names a missing or short MFA challenge secret, and accepts one of 32 bytes", () => {
    withEnv({ WEB_API_INTERNAL_URL: API }, () => {
      expect(configProblem()).toMatch(/WEB_MFA_CHALLENGE_SECRET/);
      expect(configFromEnv()).toBeNull();
    });
    withEnv({ WEB_API_INTERNAL_URL: API, WEB_MFA_CHALLENGE_SECRET: "t".repeat(31) }, () => {
      expect(configProblem()).toMatch(/WEB_MFA_CHALLENGE_SECRET/);
    });
    withEnv({ WEB_API_INTERNAL_URL: API, WEB_MFA_CHALLENGE_SECRET: MFA_SECRET }, () => {
      expect(configProblem()).toBeNull();
      expect(configFromEnv()?.mfaChallengeSecret).toBe(MFA_SECRET);
    });
    withEnv({ WEB_MFA_CHALLENGE_SECRET: MFA_SECRET }, () => {
      expect(configProblem()).toMatch(/WEB_API_INTERNAL_URL/);
    });
  });
});

describe("proxy", () => {
  const cookie = "uspace_session=tok123; uspace_csrf=csrf456";

  it.each([
    "/v1/auth/me",
    "/v1/restrictions",
    "/v1/restrictions/r1/versions",
    "/v1/delivery-alarms",
    "/v1/adapters",
    "/v1/sources",
    "/v1/restriction-requests/q1",
  ])("forwards /_bff/api%s with the session cookie as the bearer", async (p) => {
    const api = mockApi(() => Response.json({ ok: true }));
    const res = await bffWith(api.fetch).proxy(req(`/_bff/api${p}?state=active`, { method: "GET", headers: { cookie } }));
    expect(res.status).toBe(200);
    expect(api.calls[0]?.url).toBe(`${API}${p}?state=active`);
    expect(api.calls[0]?.headers.get("authorization")).toBe("Bearer tok123");
  });

  it("forwards without the cookie header", async () => {
    const api = mockApi(() => Response.json({ ok: true }));
    const res = await bffWith(api.fetch).proxy(req("/_bff/api/v1/auth/me", { method: "GET", headers: { cookie } }));
    expect(res.status).toBe(200);
    expect(api.calls[0]?.url).toBe(`${API}/v1/auth/me`);
    expect(api.calls[0]?.headers.get("authorization")).toBe("Bearer tok123");
    expect(api.calls[0]?.headers.get("cookie")).toBeNull();
  });

  it("refuses a mutating request without X-CSRF-Token", async () => {
    const api = mockApi(() => Response.json({ ok: true }));
    const res = await bffWith(api.fetch).proxy(
      req("/_bff/api/v1/restrictions/r1/activate", { method: "POST", headers: { cookie }, body: "{}" }),
    );
    expect(res.status).toBe(403);
    expect(api.calls).toHaveLength(0);
  });

  it("refuses a mutating request whose X-CSRF-Token differs from the cookie", async () => {
    const api = mockApi(() => Response.json({ ok: true }));
    const res = await bffWith(api.fetch).proxy(
      req("/_bff/api/v1/restrictions/r1/activate", {
        method: "POST",
        headers: { cookie, "x-csrf-token": "other" },
        body: "{}",
      }),
    );
    expect(res.status).toBe(403);
    expect(api.calls).toHaveLength(0);
  });

  it("forwards a mutating request whose X-CSRF-Token matches the cookie", async () => {
    const api = mockApi(() => Response.json({ ok: true }));
    const res = await bffWith(api.fetch).proxy(
      req("/_bff/api/v1/restrictions/r1/activate", {
        method: "POST",
        headers: { cookie, "x-csrf-token": "csrf456", "content-type": "application/json" },
        body: JSON.stringify({ reason: "test" }),
      }),
    );
    expect(res.status).toBe(200);
    expect(api.calls[0]?.method).toBe("POST");
    expect(api.calls[0]?.url).toBe(`${API}/v1/restrictions/r1/activate`);
    expect(api.calls[0]?.headers.get("authorization")).toBe("Bearer tok123");
  });

  it.each(["/v1/users", "/v1/policy", "/v1/audit", "/v1/auth/login", "/v1/auth/mfa", "/v1/auth/logout", "/metrics", "/v1/restrictionsX"])(
    "refuses %s, which is not on the console's list",
    async (p) => {
      const api = mockApi(() => Response.json({ ok: true }));
      const res = await bffWith(api.fetch).proxy(
        req(`/_bff/api${p}`, { method: "POST", headers: { cookie, "x-csrf-token": "csrf456" }, body: "{}" }),
      );
      expect(res.status).toBe(404);
      expect(api.calls).toHaveLength(0);
    },
  );
});

describe("Idempotency-Key", () => {
  const cookie = "uspace_session=tok123; uspace_csrf=csrf456";
  const plan = (headers: Record<string, string>, p = "/_bff/api/v1/restrictions") =>
    req(p, {
      method: "POST",
      headers: { cookie, "x-csrf-token": "csrf456", "content-type": "application/json", ...headers },
      body: JSON.stringify({ reason_text: "x" }),
    });

  it("is forwarded on POST /v1/restrictions with the bearer and the body", async () => {
    const api = mockApi(() => Response.json({ id: "r1" }, { status: 201 }));
    const res = await bffWith(api.fetch).proxy(plan({ "idempotency-key": "console-0f1e2d3c" }));
    expect(res.status).toBe(201);
    expect(api.calls[0]?.url).toBe(`${API}/v1/restrictions`);
    expect(api.calls[0]?.headers.get("idempotency-key")).toBe("console-0f1e2d3c");
    expect(api.calls[0]?.headers.get("authorization")).toBe("Bearer tok123");
    expect(JSON.parse(api.calls[0]?.body ?? "{}")).toEqual({ reason_text: "x" });
  });

  it("is not forwarded without being sent, nor on another operation, nor in another shape", async () => {
    const api = mockApi(() => Response.json({ ok: true }));
    const bff = bffWith(api.fetch);
    await bff.proxy(plan({}));
    await bff.proxy(plan({ "idempotency-key": "console-1" }, "/_bff/api/v1/restrictions/r1/activate"));
    await bff.proxy(plan({ "idempotency-key": "has spaces" }));
    expect(api.calls).toHaveLength(3);
    expect(api.calls.map((c) => c.headers.get("idempotency-key"))).toEqual([null, null, null]);
  });

  it("does not lift the CSRF check", async () => {
    const api = mockApi(() => Response.json({ id: "r1" }, { status: 201 }));
    const res = await bffWith(api.fetch).proxy(
      req("/_bff/api/v1/restrictions", { method: "POST", headers: { cookie, "idempotency-key": "console-1" }, body: "{}" }),
    );
    expect(res.status).toBe(403);
    expect(api.calls).toHaveLength(0);
  });
});

describe("logout", () => {
  const cookie = "uspace_session=tok123; uspace_csrf=csrf456";

  it("calls POST /v1/auth/logout with the bearer and clears both cookies", async () => {
    const api = mockApi(() => new Response(null, { status: 204 }));
    const res = await bffWith(api.fetch).logout(
      req("/_bff/logout", { method: "POST", headers: { cookie, "x-csrf-token": "csrf456" } }),
    );
    expect(res.status).toBe(204);
    expect(api.calls).toHaveLength(1);
    expect(api.calls[0]?.method).toBe("POST");
    expect(api.calls[0]?.url).toBe(`${API}/v1/auth/logout`);
    expect(api.calls[0]?.headers.get("authorization")).toBe("Bearer tok123");
    const cookies = setCookies(res);
    expect(cookies.get("uspace_session")).toMatch(/Max-Age=0|Expires=Thu, 01 Jan 1970/i);
    expect(cookies.get("uspace_csrf")).toMatch(/Max-Age=0|Expires=Thu, 01 Jan 1970/i);
  });

  it("clears the cookies even when the API is down", async () => {
    const f = vi.fn(() => Promise.reject(new TypeError("connect ECONNREFUSED"))) as unknown as typeof fetch;
    const res = await bffWith(f).logout(req("/_bff/logout", { method: "POST", headers: { cookie, "x-csrf-token": "csrf456" } }));
    expect(res.status).toBe(204);
    expect(setCookies(res).has("uspace_session")).toBe(true);
  });

  it("refuses a logout without X-CSRF-Token and leaves the cookies", async () => {
    const api = mockApi(() => new Response(null, { status: 204 }));
    const res = await bffWith(api.fetch).logout(req("/_bff/logout", { method: "POST", headers: { cookie } }));
    expect(res.status).toBe(403);
    expect(api.calls).toHaveLength(0);
    expect(setCookies(res).size).toBe(0);
  });
});

describe("routes", () => {
  const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../app");

  function routeFiles(dir: string): string[] {
    return readdirSync(dir).flatMap((name) => {
      const p = path.join(dir, name);
      if (statSync(p).isDirectory()) return routeFiles(p);
      return /^route\.[cm]?[jt]sx?$/.test(name) ? [path.relative(appDir, p).replaceAll("\\", "/")] : [];
    });
  }

  it("the app has exactly the three BFF routes and no ws-ticket", () => {
    expect(routeFiles(appDir).sort()).toEqual([
      "%5Fbff/api/[...path]/route.ts",
      "%5Fbff/login/route.ts",
      "%5Fbff/logout/route.ts",
    ]);
  });
});
