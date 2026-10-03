// The plan's client reference (Idempotency-Key, api/openapi.yaml
// createRestriction): a repeat with the same key and body answers the
// restriction first created, another body with the same key is a 409.
// The key is spent only when the API refused the plan with a problem (a
// 4xx with a problem body): the next submission is another plan. A call
// that got no answer (status 0), or the BFF's 502 upstream_unreachable
// or 504 upstream_timeout, may have created the restriction: the retry
// carries the same key so it is answered with that restriction, not a
// second one.
import type { CallFailure } from "../api/client";

/** A fresh client reference ([A-Za-z0-9._:-], api/openapi.yaml IdempotencyKey). */
export function clientRef(): string {
  return `console-${crypto.randomUUID()}`;
}

/** The reference to send: the held one, or a fresh one when none is held. */
export function referenceFor(held: string): string {
  return held === "" ? clientRef() : held;
}

/** The reference held after `f`: "" (a new one next time) when the plan was refused. */
export function referenceAfter(held: string, f: CallFailure): string {
  const refused = f.status >= 400 && f.status < 500 && f.problem !== null;
  return refused ? "" : held;
}
