// The occurrence report's Idempotency-Key across a failed send, through
// the console's client as the page sends it: a send that may have
// reached the API (no answer, the BFF's 502 or 504, a 500 or 503 after
// the commit) keeps its key, so the re-send is answered with the report
// first queued, never a second one; a 4xx refusal with a problem spends
// it; a queued report spends it (E-01 pairs).
import { describe, expect, it, vi } from "vitest";
import { consoleClient } from "../api/client";
import { sendOccurrence, type ApiOccurrenceCreate } from "./occurrence";

function problem(status: number, slug: string): Response {
  return new Response(JSON.stringify({ type: `https://schemas.uspace.ge/problems/${slug}`, title: "t", status, detail: "d", errors: [] }), {
    status,
    headers: { "Content-Type": "application/problem+json" },
  });
}

const queued = { id: "01K6P4B2C3D4E5F6G7H8J9KMNP", report_ref: "ANSP-OCC-2026-0007", state: "queued", deadline_at: "2026-10-05T11:25:00.000Z" };

const body: ApiOccurrenceCreate = {
  channel: "mandatory",
  occurred_at: "2026-10-02T11:20:00Z",
  became_aware_at: "2026-10-02T11:25:00Z",
  category: "airprox",
  narrative: "Synthetic airprox for the test.",
};

/** Send the report, answer the first send with `first` and the second with 202, as the page does. */
async function sendTwice(first: () => Response | Promise<Response>) {
  const keys: string[] = [];
  let n = 0;
  const f = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    keys.push(new Request(input, init).headers.get("idempotency-key") ?? "");
    n += 1;
    if (n === 1) return first();
    return Response.json(queued, { status: 202 });
  }) as unknown as typeof fetch;
  const c = consoleClient(() => "en", { onUnauthorized: () => undefined }, { fetch: f, origin: "https://console.test" });
  const one = await sendOccurrence(c, body, "");
  const two = await sendOccurrence(c, body, one.held);
  return { keys, one, two };
}

describe("the occurrence report's Idempotency-Key", () => {
  it("is sent with every report, of the contract's shape", async () => {
    const { keys, one } = await sendTwice(() => Response.json(queued, { status: 202 }));
    expect(keys[0]).toMatch(/^console-[A-Za-z0-9._:-]+$/);
    expect(one.queued).toEqual(queued);
    expect(one.held).toBe("");
  });

  for (const [name, first] of [
    ["no answer", () => Promise.reject(new DOMException("The operation timed out.", "TimeoutError"))],
    ["the BFF's 502", () => problem(502, "upstream_unreachable")],
    ["the BFF's 504", () => problem(504, "upstream_timeout")],
    ["a 500 after the commit", () => problem(500, "internal")],
    ["a 503", () => problem(503, "outbox_unavailable")],
  ] as const) {
    it(`is kept after ${name}: the outcome is unknown and the re-send carries the same key`, async () => {
      const { keys, one, two } = await sendTwice(first);
      expect(one.outcome).toBe("unknown");
      expect(one.failure).not.toBeNull();
      expect(one.held).toBe(keys[0]);
      expect(keys[1]).toBe(keys[0]);
      expect(two.queued).toEqual(queued);
    });
  }

  it("is spent after a 4xx refusal with a problem: the corrected report is another one", async () => {
    for (const [status, slug] of [
      [400, "invalid_request"],
      [409, "idempotency_conflict"],
    ] as const) {
      const { keys, one } = await sendTwice(() => problem(status, slug));
      expect(one.outcome).toBe("refused");
      expect(one.held).toBe("");
      expect(keys[1]).not.toBe(keys[0]);
      expect(keys[1]).toMatch(/^console-/);
    }
  });

  it("answers a repeat's 200 as the receipt of the report first queued", async () => {
    const { keys, one, two } = await sendTwice(() => problem(503, "outbox_unavailable"));
    expect(keys[1]).toBe(keys[0]);
    expect(two.queued?.report_ref).toBe("ANSP-OCC-2026-0007");
    expect(two.held).toBe("");
    expect(one.queued).toBeNull();
  });
});
