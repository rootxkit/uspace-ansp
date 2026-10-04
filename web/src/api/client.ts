// The console's one way to reach the API: the kit's typed client
// (openapi-fetch over the generated `paths`) on the BFF's proxy
// /_bff/api. The BFF holds the session in its HttpOnly cookie and
// forwards it as the bearer; unsafe methods carry the double-submit
// X-CSRF-Token. A non-2xx answer rejects with the kit's ApiError, which
// failureOf turns into what the page shows.
import { BFF_API_PREFIX, csrfToken } from "@rootxkit/uspace-ui/auth/client";
import { ApiError, createClient, fieldErrorsOf } from "@rootxkit/uspace-ui/api";
import type { Lang } from "@rootxkit/uspace-ui/i18n";
import type { FieldError, Problem } from "@rootxkit/uspace-ui/model";
import type { paths } from "./types";

/** What the client tells the console about the session. */
export interface SessionEvents {
  /** A call answered 401: the session is gone. */
  onUnauthorized(): void;
  /** A call answered 2xx: the session is good (again, after a sign-in). */
  onAuthorized?(): void;
}

/**
 * The console's client, on the BFF. `test` is for unit tests only: a
 * fetch and the origin a relative URL needs outside a browser.
 */
export function consoleClient(lang: () => Lang, session: SessionEvents, test?: { fetch: typeof fetch; origin: string }) {
  const client = createClient<paths>({
    baseUrl: `${test?.origin ?? ""}${BFF_API_PREFIX}`,
    csrfToken: () => csrfToken(),
    onUnauthorized: () => session.onUnauthorized(),
    lang,
    ...(test === undefined ? {} : { fetch: test.fetch }),
  });
  // A 2xx is a session the API accepted: the console is signed in (again).
  client.use({
    onResponse({ response }) {
      if (response.ok) session.onAuthorized?.();
      return undefined;
    },
  });
  return client;
}

export type ConsoleClient = ReturnType<typeof consoleClient>;

/** What a refused or failed call said, for ProblemNotice. */
export interface CallFailure {
  /** The HTTP status; 0 when the API could not be reached. */
  status: number;
  problem: Problem | null;
  /** The problem's slug (`cis_stale`, `forbidden`, ...), or null. */
  slug: string | null;
  retryAfterS: number | null;
  /** The problem's field errors, `[]` without any. */
  fieldErrors: FieldError[];
}

/** A rejection of the kit's client as a CallFailure. */
export function failureOf(err: unknown): CallFailure {
  if (err instanceof ApiError) {
    return {
      status: err.status,
      problem: err.problem,
      slug: err.slug,
      retryAfterS: err.retryAfterS,
      fieldErrors: fieldErrorsOf(err),
    };
  }
  return { status: 0, problem: null, slug: null, retryAfterS: null, fieldErrors: [] };
}

/** The refusal of a plan whose window is longer than CstrMaxDurationHours (api/openapi.yaml RestrictionCreate). */
export const CHAIN_REQUIRED = "chain_required";

/** The re-issues a chain_required refusal proposes (errors chain[i]), in order. */
export function chainProposal(f: CallFailure): FieldError[] {
  if (f.slug !== CHAIN_REQUIRED) return [];
  return f.fieldErrors
    .map((e) => ({ e, i: /^chain\[(\d+)\]/.exec(e.field) }))
    .filter((x): x is { e: FieldError; i: RegExpExecArray } => x.i !== null)
    .sort((a, b) => Number(a.i[1]) - Number(b.i[1]))
    .map((x) => x.e);
}
