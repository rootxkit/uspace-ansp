// The typed client's error mapping: the API's RFC 9457 problem (M28)
// becomes a CallFailure with its slug, its field errors and Retry-After;
// an unreachable API is status 0; a 2xx resolves; a chain_required
// refusal yields the proposed re-issues in order. Each refusal has its
// acceptance twin (E-01).
import { describe, expect, it, vi } from "vitest";
import { chainProposal, consoleClient, failureOf, type CallFailure } from "./client";

function problem(status: number, slug: string, errors: { field: string; reason: string }[] = [], headers: Record<string, string> = {}) {
  return new Response(
    JSON.stringify({ type: `https://schemas.uspace.ge/problems/${slug}`, title: "Refused", status, detail: "as the API says", instance: "/v1/restrictions", errors }),
    { status, headers: { "Content-Type": "application/problem+json", ...headers } },
  );
}

function client(answer: () => Response | Promise<Response>) {
  const onUnauthorized = vi.fn();
  const calls: Request[] = [];
  const f = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push(new Request(input, init));
    return answer();
  }) as unknown as typeof fetch;
  return { c: consoleClient(() => "en", onUnauthorized, { fetch: f, origin: "https://console.test" }), onUnauthorized, calls };
}

async function failureFrom(p: Promise<unknown>): Promise<CallFailure> {
  try {
    await p;
  } catch (err: unknown) {
    return failureOf(err);
  }
  throw new Error("the call resolved");
}

describe("consoleClient", () => {
  it("calls the BFF's proxy and resolves a 2xx with its data", async () => {
    const { c, calls } = client(() => Response.json({ restrictions: [], cis_version: "42", cis_age_s: 1 }));
    const { data } = await c.GET("/v1/restrictions", { params: { query: { state: "active" } } });
    expect(data?.cis_version).toBe("42");
    expect(new URL(calls[0]?.url ?? "").pathname).toBe("/_bff/api/v1/restrictions");
    expect(calls[0]?.headers.get("accept-language")).toBe("en");
  });

  it("maps a 400 problem to its slug and its field errors", async () => {
    const errors = [
      { field: "lower_ref", reason: "AGL is not supported for a dynamic restriction in this release" },
      { field: "geometry.coordinates[0][3]", reason: "self-intersection" },
    ];
    const { c } = client(() => problem(400, "invalid_request", errors));
    const f = await failureFrom(c.POST("/v1/restrictions/{id}/cancel", { params: { path: { id: "r1" } }, body: { reason: "x" } }));
    expect(f).toMatchObject({ status: 400, slug: "invalid_request", fieldErrors: errors, retryAfterS: null });
    expect(f.problem?.detail).toBe("as the API says");
  });

  it("maps a 503 cis_stale with Retry-After", async () => {
    const { c } = client(() => problem(503, "cis_stale", [], { "Retry-After": "30" }));
    const f = await failureFrom(c.GET("/v1/restrictions"));
    expect(f).toMatchObject({ status: 503, slug: "cis_stale", retryAfterS: 30 });
  });

  it("calls onUnauthorized on a 401, and not on a 403", async () => {
    const a = client(() => problem(401, "unauthenticated"));
    expect((await failureFrom(a.c.GET("/v1/auth/me"))).status).toBe(401);
    expect(a.onUnauthorized).toHaveBeenCalledTimes(1);
    const b = client(() => problem(403, "forbidden"));
    expect((await failureFrom(b.c.GET("/v1/auth/me"))).slug).toBe("forbidden");
    expect(b.onUnauthorized).not.toHaveBeenCalled();
  });

  it("maps an unreachable API to status 0, with nothing else claimed", async () => {
    const { c } = client(() => Promise.reject(new TypeError("fetch failed")));
    expect(await failureFrom(c.GET("/v1/adapters"))).toEqual({ status: 0, problem: null, slug: null, retryAfterS: null, fieldErrors: [] });
  });
});

describe("chainProposal", () => {
  const base: CallFailure = { status: 400, problem: null, slug: "chain_required", retryAfterS: null, fieldErrors: [] };

  it("lists the chain's re-issues in their order", () => {
    const f = {
      ...base,
      fieldErrors: [
        { field: "chain[1]", reason: "2026-10-03T12:00:00Z to 2026-10-04T12:00:00Z" },
        { field: "ends_at", reason: "longer than 24 h" },
        { field: "chain[0]", reason: "2026-10-02T12:00:00Z to 2026-10-03T12:00:00Z" },
      ],
    };
    expect(chainProposal(f).map((e) => e.field)).toEqual(["chain[0]", "chain[1]"]);
  });

  it("is empty for any other refusal", () => {
    expect(chainProposal({ ...base, slug: "invalid_request", fieldErrors: [{ field: "chain[0]", reason: "x" }] })).toEqual([]);
  });
});
