// The plan's Idempotency-Key across a failed send: a refusal with a
// problem spends it, a call that may have reached the API keeps it so
// the retry is answered with the restriction first created.
import { describe, expect, it, vi } from "vitest";
import { consoleClient, failureOf, type CallFailure } from "../api/client";
import { referenceAfter, referenceFor } from "./reference";

function problem(status: number, slug: string): Response {
  return new Response(JSON.stringify({ type: `https://schemas.uspace.ge/problems/${slug}`, title: "t", status, detail: "d", errors: [] }), {
    status,
    headers: { "Content-Type": "application/problem+json" },
  });
}

const created = { id: "r1" };

const body = {
  uspace_airspace_id: "GEOTU01",
  zone_type: "PROHIBITED",
  geometry: { type: "Polygon", coordinates: [[[44.7, 41.7], [44.8, 41.7], [44.8, 41.8], [44.7, 41.7]]] },
  lower_m: 0,
  lower_ref: "AMSL",
  upper_m: 120,
  upper_ref: "AMSL",
  starts_at: "2026-10-04T10:00:00Z",
  ends_at: "2026-10-04T11:00:00Z",
  reason_text: "test",
} as never;

/** Send the plan, fail the first answer with `first`, then retry as the editor does. */
async function sendTwice(first: () => Response | Promise<Response>): Promise<string[]> {
  const keys: string[] = [];
  let n = 0;
  const f = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    keys.push(new Request(input, init).headers.get("idempotency-key") ?? "");
    n += 1;
    if (n === 1) return first();
    return Response.json(created, { status: 201 });
  }) as unknown as typeof fetch;
  const c = consoleClient(() => "en", { onUnauthorized: () => undefined }, { fetch: f, origin: "https://console.test" });
  let held = "";
  for (let attempt = 0; attempt < 2; attempt++) {
    held = referenceFor(held);
    try {
      await c.POST("/v1/restrictions", { params: { header: { "Idempotency-Key": held } }, body });
      held = "";
    } catch (err: unknown) {
      held = referenceAfter(held, failureOf(err));
    }
  }
  return keys;
}

function failure(status: number, withProblem: boolean): CallFailure {
  return {
    status,
    problem: withProblem ? { type: "https://schemas.uspace.ge/problems/x", title: "t", status, detail: "d" } : null,
    slug: withProblem ? "x" : null,
    retryAfterS: null,
    fieldErrors: [],
  } as CallFailure;
}

describe("the plan's Idempotency-Key", () => {
  it("is reused on the retry after the call timed out without an answer", async () => {
    const keys = await sendTwice(() => Promise.reject(new DOMException("The operation timed out.", "TimeoutError")));
    expect(keys).toHaveLength(2);
    expect(keys[0]).not.toBe("");
    expect(keys[1]).toBe(keys[0]);
  });

  it("is reused on the retry after the BFF's 504 upstream_timeout", async () => {
    const keys = await sendTwice(() => problem(504, "upstream_timeout"));
    expect(keys[1]).toBe(keys[0]);
  });

  it("is reused on the retry after the BFF's 502 upstream_unreachable", async () => {
    const keys = await sendTwice(() => problem(502, "upstream_unreachable"));
    expect(keys[1]).toBe(keys[0]);
  });

  it("is replaced after a 4xx refusal with a problem", async () => {
    for (const [status, slug] of [
      [400, "invalid_request"],
      [409, "conflict"],
      [422, "chain_required"],
    ] as const) {
      const keys = await sendTwice(() => problem(status, slug));
      expect(keys).toHaveLength(2);
      expect(keys[1]).not.toBe(keys[0]);
      expect(keys[1]).toMatch(/^console-[A-Za-z0-9._:-]+$/);
    }
  });

  it("keeps the key on a status 0, a 502, a 504 and a 4xx without a problem body", () => {
    expect(referenceAfter("console-1", failure(0, false))).toBe("console-1");
    expect(referenceAfter("console-1", failure(502, true))).toBe("console-1");
    expect(referenceAfter("console-1", failure(504, true))).toBe("console-1");
    expect(referenceAfter("console-1", failure(404, false))).toBe("console-1");
  });

  it("spends the key on a 4xx with a problem body", () => {
    expect(referenceAfter("console-1", failure(400, true))).toBe("");
    expect(referenceAfter("console-1", failure(409, true))).toBe("");
  });

  it("is fresh when none is held and kept while held", () => {
    const k = referenceFor("");
    expect(k).toMatch(/^console-/);
    expect(referenceFor(k)).toBe(k);
  });
});
