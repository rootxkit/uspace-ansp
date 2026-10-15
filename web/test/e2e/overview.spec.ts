// The overview in the browser, through the real BFF (`next start`)
// against test/mock-api.mjs: it is the page after sign-in, every figure
// starts as the API states it (no restriction, no alarm, nothing
// awaiting, one adapter of three running), and each one moves when the
// API's state does: a notice received and escalated, a restriction
// planned and activated (its delivery alarm open), the outbox delivering
// it (the alarm cleared). Every wait is on a condition, never on time.
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { typeVertices } from "./outline";

// The mock's test accounts and code (test/mock-api.mjs), not credentials.
const SUPER = { username: "super1", password: "super1-test-password" };
const ADMIN = { username: "admin1", password: "admin1-test-password" };
const VIEWER = { username: "viewer1", password: "viewer1-test-password" };
const CODE = "246810";

async function control(request: APIRequestContext, path: string, data: Record<string, unknown>) {
  expect((await request.post(path, { data })).ok()).toBe(true);
}

/** Signs in; super1 enrols at its first sign-in, the others are enrolled. */
async function signIn(page: Page, who = SUPER) {
  await page.goto("/en/login");
  await page.getByLabel("Username").fill(who.username);
  await page.getByLabel("Password").fill(who.password);
  await page.getByTestId("login-submit").click();
  if (who === SUPER) await expect(page.getByTestId("enrolment-qr")).toBeVisible();
  await page.getByLabel(/Code from your authenticator/).fill(CODE);
  await page.getByTestId("login-submit").click();
  await expect(page).toHaveURL(/\/en\/overview$/);
}

/** The status of a call through the BFF from the page (its cookies, same origin). */
async function bffStatus(page: Page, path: string, method = "GET"): Promise<number> {
  return page.evaluate(async ([p, m]) => (await fetch(`/_bff/api${p}`, { method: m })).status, [path, method] as const);
}

test.beforeEach(async ({ request }) => {
  expect((await request.post("/__mock/reset")).ok()).toBe(true);
});

test("the overview is the page after sign-in and its figures follow the API", async ({ page, request }) => {
  await signIn(page);
  await expect(page).toHaveURL(/\/en\/overview$/);
  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
  const nav = page.getByRole("navigation", { name: "Main navigation" });
  await expect(nav.getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("status-bar")).toHaveAttribute("data-connection", "live");

  // As the API states it at start.
  await expect(page.getByTestId("kpi-active")).toHaveAttribute("data-value", "0");
  await expect(page.getByTestId("kpi-alarms")).toHaveAttribute("data-value", "0");
  await expect(page.getByTestId("kpi-alarms")).toContainText("None open");
  await expect(page.getByTestId("overview-alarms-none")).toBeVisible();
  await expect(page.getByTestId("kpi-awaiting")).toHaveAttribute("data-value", "0");
  await expect(page.getByTestId("kpi-awaiting")).toContainText("None awaiting");
  await expect(page.getByTestId("overview-inbox-none")).toBeVisible();
  await expect(page.getByTestId("nav-inbox-badge")).toHaveCount(0);
  const adapters = page.getByTestId("kpi-adapters");
  await expect(adapters).toHaveAttribute("data-value", "1");
  await expect(adapters).toContainText("1 of 3");
  await expect(adapters).toContainText("1 silent, 1 disabled");
  await expect(page.locator('[data-testid="overview-sources"] [data-adapter="sbs-1"]')).toContainText("Disabled");
  await expect(page.locator('[data-testid="overview-sources"] [data-adapter="json-1"]')).toContainText("Silent");
  await expect(page.getByTestId("kpi-cis")).toHaveAttribute("data-value", /^\d+$/);
  const requests = page.getByTestId("kpi-requests");
  await expect(requests).toHaveAttribute("data-value", "1");
  await expect(requests).toContainText("Awaiting a supervisor");
  await expect(requests).toContainText("Oldest received");
  // The accounts are an admin's: no tile, and the API refuses the summary.
  await expect(page.getByTestId("kpi-users")).toHaveCount(0);
  expect(await bffStatus(page, "/v1/users/summary")).toBe(403);

  // A notice received: awaiting, in the figure, the sidebar and the list; escalated: said so.
  await control(request, "/__mock/notice", { ack_id: "01K6P0N0000000000000000001", kind: "nonconformance", received_at: "2026-10-02T12:00:00.000Z" });
  await expect(page.getByTestId("kpi-awaiting")).toHaveAttribute("data-value", "1");
  await expect(page.getByTestId("kpi-awaiting")).toContainText("Awaiting a person");
  await expect(page.getByTestId("nav-inbox-badge")).toContainText("1 awaiting");
  await expect(page.locator('[data-testid="overview-inbox"] [data-ack="01K6P0N0000000000000000001"]')).toHaveAttribute("data-group", "awaiting");
  await control(request, "/__mock/escalate", { ack_id: "01K6P0N0000000000000000001" });
  await expect(page.getByTestId("kpi-awaiting")).toContainText("1 escalated");
  await expect(page.locator('[data-testid="overview-inbox"] [data-ack="01K6P0N0000000000000000001"]')).toHaveAttribute("data-group", "escalated");

  // A restriction planned and activated: active, with its delivery alarm open.
  await page.getByTestId("overview-plan").click();
  await expect(page).toHaveURL(/\/en\/restrictions\/new$/);
  await typeVertices(page, [
    [44.78, 41.7],
    [44.82, 41.7],
    [44.82, 41.73],
    [44.78, 41.73],
  ]);
  await page.getByLabel("U-space airspace (ED-318 identifier)").fill("GEOTU01");
  await page.getByRole("textbox", { name: "Lower limit (m)", exact: true }).fill("0");
  await page.getByRole("textbox", { name: "Upper limit (m)", exact: true }).fill("1200");
  await page.getByLabel("Starts, UTC").fill("2026-10-05T12:00");
  await page.getByLabel("Ends, UTC").fill("2026-10-05T16:00");
  await page.getByRole("textbox", { name: "Reason", exact: true }).fill("Search and rescue operation (synthetic)");
  await page.getByRole("button", { name: "Plan", exact: true }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Plan and send" }).click();
  await expect(page).toHaveURL(/\/en\/restrictions\/[0-9A-Z]{26}$/);
  const id = new URL(page.url()).pathname.split("/").pop() ?? "";
  await page.getByTestId("act-activate").click();
  await page.getByRole("alertdialog").getByLabel("Reason").fill("Rescue helicopter on scene (synthetic)");
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByTestId("restriction-detail")).toHaveAttribute("data-state", "active");

  await expect(nav.getByRole("link", { name: "Restrictions", exact: true })).toHaveAttribute("aria-current", "page");
  await nav.getByRole("link", { name: "Overview" }).click();
  await expect(page).toHaveURL(/\/en\/overview$/);
  await expect(page.getByTestId("kpi-active")).toHaveAttribute("data-value", "1");
  await expect(page.getByTestId("kpi-alarms")).toHaveAttribute("data-value", "1");
  await expect(page.getByTestId("kpi-alarms")).toContainText("1 not acknowledged");
  await expect(page.getByTestId("overview-alarms")).toContainText("Active here, not yet published to the CISP");
  await expect(page.getByTestId("overview-recent").locator('tr[data-state="active"]')).toHaveCount(1);

  // The outbox delivers: the stream carries it and the alarm leaves the figure.
  await control(request, "/__mock/deliver", { id });
  await expect(page.getByTestId("kpi-alarms")).toHaveAttribute("data-value", "0");
  await expect(page.getByTestId("overview-alarms-none")).toBeVisible();
  await expect(page.getByTestId("kpi-active")).toHaveAttribute("data-value", "1");
});

test("the admin's overview counts the console accounts; nobody else is shown or served them", async ({ page, request }) => {
  await signIn(page, ADMIN);
  const users = page.getByTestId("kpi-users");
  await expect(users).toHaveAttribute("data-value", "3");
  await expect(users).toContainText("Active console accounts");
  await expect(users).toContainText("0 disabled, 1 admins, 3 in all");
  // The tile names no account: counts only.
  await expect(users).not.toContainText("admin1");
  await control(request, "/__mock/account", { username: "viewer1", status: "disabled" });
  await page.reload();
  await expect(users).toHaveAttribute("data-value", "2");
  await expect(users).toContainText("1 disabled, 1 admins, 3 in all");
  // The BFF forwards that one path for GET and nothing else.
  expect(await bffStatus(page, "/v1/users/summary")).toBe(200);
  expect(await bffStatus(page, "/v1/users/summary", "POST")).toBe(405);
  expect(await bffStatus(page, "/v1/users")).toBe(404);
  // Without a session the API answers 401 through the BFF.
  expect((await request.get("/_bff/api/v1/users/summary")).status()).toBe(401);
});

test("a viewer's overview has no accounts, requests or occurrence tile and the API refuses it each summary", async ({ page }) => {
  await signIn(page, VIEWER);
  await expect(page.getByTestId("kpi-active")).toHaveAttribute("data-value", "0");
  await expect(page.getByTestId("kpi-users")).toHaveCount(0);
  await expect(page.getByTestId("kpi-requests")).toHaveCount(0);
  await expect(page.getByTestId("kpi-occurrences")).toHaveCount(0);
  // The manned picture's count is every role's.
  await expect(page.getByTestId("kpi-manned")).toHaveAttribute("data-value", "0");
  expect(await bffStatus(page, "/v1/users/summary")).toBe(403);
  expect(await bffStatus(page, "/v1/restriction-requests/summary")).toBe(403);
  expect(await bffStatus(page, "/v1/occurrences/summary")).toBe(403);
  expect(await bffStatus(page, "/v1/restriction-requests")).toBe(403);
  // Its requests page opens a request by its id and says why there is no list.
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Restriction requests" }).click();
  await expect(page.getByTestId("requests-no-list")).toBeVisible();
  await expect(page.getByTestId("requests-pending")).toHaveCount(0);
});

test("the supervisor's requests tile counts the requests awaiting a decision and follows a decision", async ({ page, request }) => {
  await signIn(page);
  const tile = page.getByTestId("kpi-requests");
  await expect(tile).toHaveAttribute("data-value", "1");
  expect(await bffStatus(page, "/v1/restriction-requests/summary")).toBe(200);
  expect(await bffStatus(page, "/v1/restriction-requests/summary", "DELETE")).toBe(405);
  expect((await request.get("/_bff/api/v1/restriction-requests/summary")).status()).toBe(401);
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Restriction requests" }).click();
  await page.locator('[data-testid="requests-pending"] [data-request="01K6P0R0000000000000000001"]').getByRole("link").click();
  await expect(page.getByTestId("request")).toHaveAttribute("data-state", "received");
  await page.getByTestId("request-decline").click();
  await page.getByRole("alertdialog").getByLabel("Reason").fill("Outside the event's hours (synthetic)");
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByTestId("request")).toHaveAttribute("data-state", "declined");
  await expect(page.getByTestId("requests-none-waiting")).toBeVisible();
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Overview" }).click();
  await expect(tile).toHaveAttribute("data-value", "0");
  await expect(tile).toContainText("None waiting");
});

test("the supervisor's occurrence tile counts the reports by the state of their delivery", async ({ page, request }) => {
  await signIn(page);
  const tile = page.getByTestId("kpi-occurrences");
  await expect(tile).toHaveAttribute("data-value", "0");
  await expect(tile).toContainText("None submitted");
  expect(await bffStatus(page, "/v1/occurrences/summary", "PUT")).toBe(405);
  expect((await request.get("/_bff/api/v1/occurrences/summary")).status()).toBe(401);

  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Report an occurrence" }).click();
  await page.getByTestId("occ-occurred_at").fill("2026-10-02T11:20");
  await page.getByTestId("occ-became_aware_at").fill("2026-10-02T11:25");
  await page.getByTestId("occ-narrative").fill("Synthetic airprox between a UAS and a manned aircraft.");
  await page.getByTestId("occ-submit").click();
  await expect(page.getByTestId("occurrence-queued")).toContainText("ANSP-OCC-2026-0001");
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Overview" }).click();
  await expect(tile).toHaveAttribute("data-value", "1");
  await expect(tile).toContainText("1 queued to the authority");
  await expect(tile).toContainText("0 sent, 1 queued, 0 failed, 0 abandoned, 0 cancelled");

  // The outbox's outcome, as the API states it: sent, then a failed one.
  await control(request, "/__mock/occurrence", { state: "sent" });
  await page.reload();
  await expect(tile).toContainText("All sent");
  await expect(tile).toContainText("1 sent, 0 queued");
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Report an occurrence" }).click();
  await page.getByTestId("occ-occurred_at").fill("2026-10-02T12:20");
  await page.getByTestId("occ-became_aware_at").fill("2026-10-02T12:25");
  await page.getByTestId("occ-narrative").fill("Second synthetic report.");
  await page.getByTestId("occ-submit").click();
  await expect(page.getByTestId("occurrence-queued")).toContainText("ANSP-OCC-2026-0002");
  await control(request, "/__mock/occurrence", { state: "failed" });
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Overview" }).click();
  await expect(tile).toHaveAttribute("data-value", "2");
  await expect(tile).toContainText("1 failed or abandoned");
});

test("the manned tile counts the picture as manned-feed holds it, read from the API through the BFF and not from a stream", async ({ page, request }) => {
  await control(request, "/__mock/manned", { icao24: "4ca7b5", callsign: "TST123" });
  await control(request, "/__mock/manned", { icao24: "4ca7b6", callsign: "OTH1", relevant: false });
  await signIn(page, VIEWER);
  const tile = page.getByTestId("kpi-manned");
  await expect(tile).toHaveAttribute("data-value", "2");
  await expect(tile).toContainText("Manned aircraft in the picture");
  await expect(tile).toContainText("2 live, 0 stale, 0 source disabled; 1 relevant to U-space");
  await expect(tile).toContainText("Nothing degraded");
  await expect(tile).not.toContainText("TST123");
  // The adapter switched off: the feed ages its aircraft and says the feed is degraded.
  await control(request, "/__mock/adapter", { id: "replay-1", state: "disabled", who: "admin1" });
  await control(request, "/__mock/manned", { icao24: "4ca7b5", state: "source_disabled" });
  await page.reload();
  await expect(tile).toContainText("1 live, 0 stale, 1 source disabled");
  await expect(tile).toHaveAttribute("data-degraded", "adapters_silent");
  await expect(tile).toContainText("Degraded: adapters_silent");
  // Read from the API's summary through the BFF with the session; the overview opens no manned stream.
  const calls = (await (await request.get("/__mock/requests")).json()) as { method: string; path: string; authorization: boolean }[];
  expect(calls).toContainEqual(expect.objectContaining({ method: "GET", path: "/v1/manned-traffic/summary", authorization: true }));
  expect(calls.filter((c) => c.method === "WS" && c.path === "/v1/manned-traffic/stream")).toHaveLength(0);
  expect(await bffStatus(page, "/v1/manned-traffic/summary", "POST")).toBe(405);
  expect((await request.get("/_bff/api/v1/manned-traffic/summary")).status()).toBe(401);
});

type Recorded = { method: string; path: string; authorization: boolean };

async function recorded(request: APIRequestContext): Promise<Recorded[]> {
  return (await (await request.get("/__mock/requests")).json()) as Recorded[];
}

/** How many times the API was asked GET `path`. */
async function asked(request: APIRequestContext, path: string): Promise<number> {
  return (await recorded(request)).filter((c) => c.method === "GET" && c.path === path).length;
}

/** The session cookie the browser holds, or null. */
async function sessionCookie(page: Page): Promise<string | null> {
  const c = (await page.context().cookies()).find((k) => k.name === "uspace_session");
  return c === undefined || c.value === "" ? null : c.value;
}

// The live regression of 2026-10-15: one data route answering 401 (the
// manned summary) or 501 (the adapters) ended the whole session. Each
// route now fails in its own tile; the session is asked about on GET
// /v1/auth/me and stays.
test("a summary answering 401 and the adapters answering 501 while the session is live leave the admin signed in", async ({ page, request }) => {
  await signIn(page, ADMIN);
  const before = await sessionCookie(page);
  expect(before).not.toBeNull();
  await control(request, "/__mock/fail", { path: "/v1/manned-traffic/summary", status: 401 });
  await control(request, "/__mock/fail", { path: "/v1/adapters", status: 501 });
  const meBefore = await asked(request, "/v1/auth/me");
  await page.reload();

  // Each tile says what it could not read; neither is a sign-out.
  const manned = page.getByTestId("kpi-manned");
  await expect(manned).toContainText("Could not be read");
  await expect(manned).toHaveAttribute("data-value", "");
  const adapters = page.getByTestId("kpi-adapters");
  await expect(adapters).toHaveAttribute("data-failure", "501");
  await expect(adapters).toContainText("Not served by this API yet");
  await expect(page.getByTestId("overview-adapters-not-served")).toContainText("does not serve this operation yet");
  // The other tiles are read as usual.
  await expect(page.getByTestId("kpi-users")).toHaveAttribute("data-value", "3");

  // The 401 asked the session's own read, which accepted it, and the
  // summary is read again on its period: still signed in after it.
  await expect.poll(() => asked(request, "/v1/auth/me"), { timeout: 15_000 }).toBeGreaterThan(meBefore + 1);
  const firstReads = await asked(request, "/v1/manned-traffic/summary");
  await expect.poll(() => asked(request, "/v1/manned-traffic/summary"), { timeout: 15_000 }).toBeGreaterThan(firstReads);
  await expect(page.getByTestId("signed-out")).toHaveCount(0);
  await expect(page.getByTestId("account")).toContainText("admin1");
  expect(await sessionCookie(page)).toBe(before);
  expect(await bffStatus(page, "/v1/auth/me")).toBe(200);
  // The BFF passes each answer on as the API gave it, and the cookie stays.
  expect(await bffStatus(page, "/v1/manned-traffic/summary")).toBe(401);
  expect(await bffStatus(page, "/v1/adapters")).toBe(501);
  expect(await sessionCookie(page)).toBe(before);

  // The console goes on: another page, and the summary back.
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Restrictions", exact: true }).click();
  await expect(page).toHaveURL(/\/en\/restrictions$/);
  await expect(page.getByTestId("signed-out")).toHaveCount(0);
  await control(request, "/__mock/fail", { path: "/v1/manned-traffic/summary", status: null });
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Overview" }).click();
  await expect(manned).toHaveAttribute("data-value", "0");
});

// Presence (E-01): the session really ends. The same data route's 401,
// now with the session gone from the API, signs the console out and the
// BFF clears the cookie: fail closed.
test("a real session expiry still signs the user out without a reload, and the cookie goes", async ({ page, request }) => {
  await signIn(page, ADMIN);
  expect(await sessionCookie(page)).not.toBeNull();
  await control(request, "/__mock/expire", {});
  // No reload: the next periodic read of a summary finds the session gone.
  await expect(page.getByTestId("signed-out")).toContainText("Signed out: your session has ended.", { timeout: 15_000 });
  await expect.poll(() => sessionCookie(page)).toBeNull();
  expect(await bffStatus(page, "/v1/auth/me")).toBe(401);
  await page.getByRole("link", { name: "Sign in again" }).click();
  await expect(page).toHaveURL(/\/en\/login$/);
});

test("a real session expiry signs out even while a data route answers 501", async ({ page, request }) => {
  await signIn(page, VIEWER);
  await control(request, "/__mock/fail", { path: "/v1/adapters", status: 501 });
  await page.reload();
  await expect(page.getByTestId("kpi-adapters")).toHaveAttribute("data-failure", "501");
  await expect(page.getByTestId("signed-out")).toHaveCount(0);
  await control(request, "/__mock/expire", {});
  await page.reload();
  await expect(page.getByTestId("signed-out")).toContainText("Signed out");
  await expect.poll(() => sessionCookie(page)).toBeNull();
});
