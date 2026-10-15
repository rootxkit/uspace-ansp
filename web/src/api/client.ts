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
  /**
   * The session is gone: GET /v1/auth/me answered 401, or another call
   * answered 401 and GET /v1/auth/me, asked again, did not answer 2xx.
   */
  onUnauthorized(): void;
  /** A call answered 2xx: the session is good (again, after a sign-in). */
  onAuthorized?(): void;
}

/** The session's own read (api/openapi.yaml getMe): the one answer that says whether it is live. */
export const SESSION_PATH = "/v1/auth/me";

/**
 * The console's client, on the BFF. `test` is for unit tests only: a
 * fetch and the origin a relative URL needs outside a browser.
 *
 * Who decides that the session is gone (fail closed): a 401 from GET
 * /v1/auth/me is the session refused and signs the console out. A 401
 * from any other operation is that operation's answer, which need not
 * be about the session; the console asks GET /v1/auth/me once (one
 * question at a time however many calls answered 401) and signs out
 * unless that answers 2xx. An unreachable API or any other answer to the
 * question also signs out. A 5xx or 501 from a data route is that
 * route's failure and never touches the session. The kit's own
 * `onUnauthorized` (any 401, uspace-ui src/api/client.ts) is not used.
 */
export function consoleClient(lang: () => Lang, session: SessionEvents, test?: { fetch: typeof fetch; origin: string }) {
  const baseUrl = `${test?.origin ?? ""}${BFF_API_PREFIX}`;
  const doFetch: typeof fetch = test?.fetch ?? ((input, init) => fetch(input, init));
  const client = createClient<paths>({
    baseUrl,
    csrfToken: () => csrfToken(),
    lang,
    ...(test === undefined ? {} : { fetch: test.fetch }),
  });
  // One sign-out per run of refusals: a page of ten requests that all
  // find the session gone signs out once; a 2xx in between re-arms it.
  let armed = true;
  const signedOut = (): void => {
    if (!armed) return;
    armed = false;
    session.onUnauthorized();
  };
  // Counts the 2xx answers: a question asked before the latest 2xx is
  // answered about an older session (a sign-in in another tab since), and
  // its "no" is not the session's state any more.
  let accepted = 0;
  let asking: Promise<void> | null = null;
  const confirmSession = (): Promise<void> => {
    asking ??= (async () => {
      const askedAt = accepted;
      const no = (): void => {
        if (accepted === askedAt) signedOut();
      };
      try {
        const res = await doFetch(`${baseUrl}${SESSION_PATH}`, {
          credentials: "same-origin",
          cache: "no-store",
          headers: { Accept: "application/json", "Accept-Language": lang() },
        });
        await res.body?.cancel().catch(() => undefined);
        if (!res.ok) no();
      } catch {
        no();
      } finally {
        asking = null;
      }
    })();
    return asking;
  };
  // Runs before the kit's middleware (openapi-fetch calls onResponse in
  // reverse order), which rejects every non-2xx with an ApiError.
  client.use({
    onResponse({ response, schemaPath }) {
      if (response.ok) {
        // A 2xx is a session the API accepted: signed in (again).
        accepted += 1;
        armed = true;
        session.onAuthorized?.();
      } else if (response.status === 401) {
        if (schemaPath === SESSION_PATH) signedOut();
        else void confirmSession();
      }
      return undefined;
    },
  });
  return Object.assign(client, {
    /**
     * Asks GET /v1/auth/me whether the session is live and signs out
     * unless it answers 2xx: for a refusal that is not the session's own
     * answer (a 401 of another call, a 4401 close of a stream that is not
     * the API's restriction stream).
     */
    confirmSession,
  });
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
