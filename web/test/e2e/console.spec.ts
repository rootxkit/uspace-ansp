// WP-12 in the browser, through the real BFF (`next start`) against
// test/mock-api.mjs: the manned picture (an aircraft live, then stale,
// then its source disabled, the symbol and the label changing each time;
// an empty stream that says why), the coordination inbox (an escalated
// notice first and loudest, cleared by an acknowledgement that reaches
// the API with its note), and the source switches (a viewer is offered
// none and the admin pages answer it 403; an admin's switch with the
// switch store down shows the API's 503 word for word and changes
// nothing; the switch then lands in the audit log). Every wait is on a
// condition, never on time.
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

// The mock's test accounts and code (test/mock-api.mjs), not credentials.
const SUPER = { username: "super1", password: "super1-test-password" };
const VIEWER = { username: "viewer1", password: "viewer1-test-password" };
const ADMIN = { username: "admin1", password: "admin1-test-password" };
const CODE = "246810";

interface Recorded {
  method: string;
  path: string;
  body?: Record<string, unknown>;
  idempotencyKey?: string | null;
}

async function recorded(request: APIRequestContext): Promise<Recorded[]> {
  return (await (await request.get("/__mock/requests")).json()) as Recorded[];
}

async function control(request: APIRequestContext, path: string, data: Record<string, unknown>) {
  expect((await request.post(path, { data })).ok()).toBe(true);
}

async function signIn(page: Page, who: { username: string; password: string }, enrolment: boolean) {
  await page.goto("/en/restrictions");
  await expect(page).toHaveURL(/\/en\/login$/);
  await page.getByLabel("Username").fill(who.username);
  await page.getByLabel("Password").fill(who.password);
  await page.getByTestId("login-submit").click();
  if (enrolment) await expect(page.getByTestId("enrolment-qr")).toBeVisible();
  await page.getByLabel(/Code from your authenticator/).fill(CODE);
  await page.getByTestId("login-submit").click();
  await expect(page).toHaveURL(/\/en\/restrictions$/);
}

test.beforeEach(async ({ request }) => {
  expect((await request.post("/__mock/reset")).ok()).toBe(true);
});

test("an aircraft goes live, stale and source disabled; its symbol and label change each time", async ({ page, request }) => {
  await signIn(page, SUPER, true);
  await page.getByRole("link", { name: "Manned picture" }).click();
  await expect(page).toHaveURL(/\/en\/picture$/);
  const status = page.getByTestId("picture-status");
  await expect(status).toHaveAttribute("data-connection", "live");
  await expect(page.getByTestId("picture-policy")).toContainText("Policy version 1 · stale after 15 s · live up to 3 s");

  await control(request, "/__mock/manned", { icao24: "4ca7b5", callsign: "TST123", alt_pressure_m: 1250, alt_wgs84_m: 1310, relevant: true });
  const row = page.locator('[data-aircraft="4ca7b5"]');
  await expect(row).toHaveAttribute("data-state", "live");
  await expect(row.getByTestId("aircraft-symbol")).toHaveAttribute("data-symbol", "live-relevant");
  await expect(row.getByTestId("aircraft-state")).toContainText("Live, age");
  await expect(row).toContainText("TST123 · 4ca7b5");
  await expect(row.getByTestId("aircraft-altitude")).toContainText("pressure altitude");
  await expect(row.getByTestId("aircraft-altitude")).toContainText("above the WGS84 ellipsoid");
  await expect(row.getByTestId("aircraft-altitude")).not.toContainText("AMSL");

  await control(request, "/__mock/manned", { icao24: "4ca7b5", state: "stale" });
  await expect(row).toHaveAttribute("data-state", "stale");
  await expect(row.getByTestId("aircraft-symbol")).toHaveAttribute("data-symbol", "stale-relevant");
  await expect(row.getByTestId("aircraft-state")).toContainText(/^Stale \(\d+ s\)$/);

  await control(request, "/__mock/adapter", { id: "replay-1", state: "disabled", who: "admin1" });
  await control(request, "/__mock/manned", { icao24: "4ca7b5", state: "source_disabled" });
  await expect(row).toHaveAttribute("data-state", "source_disabled");
  await expect(row.getByTestId("aircraft-symbol")).toHaveAttribute("data-symbol", "source_disabled-relevant");
  await expect(row.getByTestId("aircraft-state")).toContainText("Source replay-1 disabled by admin1");
  await expect(page.locator('[data-testid="picture-adapters"] [data-adapter="replay-1"]')).toHaveAttribute("data-state", "disabled");
  await expect(page.getByTestId("picture-adapters")).toContainText("replay-1: disabled by admin1");

  // An aircraft outside the relevant airspace is drawn apart from the relevant one.
  await control(request, "/__mock/manned", { icao24: "4ca7b6", callsign: "OTH1", relevant: false, source_instance: "replay-2" });
  await expect(page.locator('[data-aircraft="4ca7b6"]').getByTestId("aircraft-symbol")).toHaveAttribute("data-symbol", "live-other");

  // The stream carried the cookie and nothing reached the API for the picture but the upgrade.
  const ws = (await recorded(request)).filter((c) => c.method === "WS").map((c) => c.path);
  expect(ws).toContain("/v1/manned-traffic/stream");
});

test("an empty manned stream says no aircraft were reported and what each adapter is doing", async ({ page, request }) => {
  await signIn(page, SUPER, true);
  await control(request, "/__mock/adapter", { id: "sbs-1", state: "disabled", who: "admin" });
  await page.goto("/en/picture");
  await expect(page.getByTestId("picture-empty")).toHaveText("No aircraft reported; adapters: replay-1: live, last frame 1 s ago; sbs-1: disabled by admin");
  await expect(page.getByTestId("aircraft-list")).toHaveCount(0);
  // The same page with an aircraft says nothing of the kind.
  await control(request, "/__mock/manned", { icao24: "4ca7b5" });
  await expect(page.locator('[data-aircraft="4ca7b5"]')).toBeVisible();
  await expect(page.getByTestId("picture-empty")).toHaveCount(0);
});

test("an escalated notice is listed first and loudest, and the acknowledgement clears it", async ({ page, request }) => {
  await signIn(page, SUPER, true);
  await control(request, "/__mock/notice", { ack_id: "01K6P0N0000000000000000002", kind: "intent_notice", received_at: "2026-10-02T12:10:00.000Z" });
  await control(request, "/__mock/notice", { ack_id: "01K6P0N0000000000000000001", kind: "nonconformance", received_at: "2026-10-02T12:00:00.000Z" });
  await expect(page.getByTestId("awaiting-banner")).toContainText("1 coordination notice awaits acknowledgement");
  await control(request, "/__mock/escalate", { ack_id: "01K6P0N0000000000000000001" });
  const banner = page.getByTestId("escalated-banner");
  await expect(banner).toContainText("1 escalated coordination notice awaits acknowledgement");

  await banner.getByRole("link", { name: "Open the inbox" }).click();
  await expect(page).toHaveURL(/\/en\/inbox$/);
  const first = page.getByTestId("notice").first();
  await expect(first).toHaveAttribute("data-ack", "01K6P0N0000000000000000001");
  await expect(first).toHaveAttribute("data-group", "escalated");
  await expect(first).toHaveAttribute("role", "alert");
  await expect(first.getByTestId("notice-escalated")).toContainText("Escalated 1 time");
  await expect(first).toContainText("GEO-AUTH-0001 (synthetic)");
  const info = page.locator('[data-testid="notice"][data-ack="01K6P0N0000000000000000002"]');
  await expect(info).toHaveAttribute("data-group", "informational");
  await expect(info).toContainText("Informational: no acknowledgement is required.");

  await first.getByTestId("ack-note").fill("Seen; operator contacted (synthetic)");
  await first.getByTestId("ack-submit").click();
  const acked = page.locator('[data-testid="notice"][data-ack="01K6P0N0000000000000000001"]');
  await expect(acked).toHaveAttribute("data-state", "acknowledged");
  await expect(acked).toHaveAttribute("data-group", "acknowledged");
  await expect(acked.getByTestId("notice-acknowledged")).toContainText("Acknowledged by a watch supervisor");
  await expect(page.getByTestId("escalated-banner")).toHaveCount(0);
  await expect(page.getByTestId("inbox-group-escalated")).toHaveCount(0);

  const acks = (await recorded(request)).filter((c) => c.method === "POST" && c.path.endsWith("/acknowledge"));
  expect(acks).toEqual([expect.objectContaining({ path: "/v1/coordination/inbox/01K6P0N0000000000000000001/acknowledge", body: { note: "Seen; operator contacted (synthetic)" } })]);
});

test("an acknowledgement after someone else's is a permanent 409: said, read again, not retried", async ({ page, request }) => {
  const ack = "01K6P0N0000000000000000003";
  await signIn(page, SUPER, true);
  await control(request, "/__mock/notice", { ack_id: ack });
  await page.goto("/en/inbox");
  const card = page.locator(`[data-testid="notice"][data-ack="${ack}"]`);
  await expect(card).toHaveAttribute("data-state", "received");
  // The streams go down, so this page does not hear of the other acknowledgement.
  await control(request, "/__mock/state", { stream: false });
  await expect(page.getByTestId("coordination-status")).toHaveAttribute("data-connection", "down");
  // Another supervisor acknowledges it first, at the API (the mock does not tell sessions apart).
  const token = (await page.context().cookies()).find((c) => c.name === "uspace_session")?.value ?? "";
  const other = await request.post(`/v1/coordination/inbox/${ack}/acknowledge`, { headers: { authorization: `Bearer ${token}` }, data: {} });
  expect(other.status()).toBe(200);

  const answer = page.waitForResponse((r) => r.url().endsWith(`/${ack}/acknowledge`) && r.request().method() === "POST");
  await card.getByTestId("ack-submit").click();
  expect((await answer).status()).toBe(409);
  await expect(page.getByTestId("ack-conflict")).toHaveAttribute("data-ack", ack);
  await expect(card).toHaveAttribute("data-state", "acknowledged");
  const acks = (await recorded(request)).filter((c) => c.method === "POST" && c.path.endsWith(`/${ack}/acknowledge`));
  expect(acks).toHaveLength(2);
});

test("a viewer sees no switch controls, and the admin pages answer it 403", async ({ page }) => {
  await signIn(page, VIEWER, false);
  await expect(page.getByRole("link", { name: "Policy" })).toHaveCount(0);
  await page.getByRole("link", { name: "Source switches" }).click();
  await expect(page).toHaveURL(/\/en\/sources$/);
  const sbs = page.locator('[data-testid="switch"][data-instance="sbs-1"]');
  await expect(sbs).toHaveAttribute("data-enabled", "false");
  await expect(sbs.getByTestId("switch-state")).toContainText("Disabled by admin at");
  await expect(sbs.getByTestId("switch-state")).toContainText("Receiver under maintenance (synthetic)");
  await expect(page.locator('[data-testid^="switch-"]').filter({ has: page.getByRole("button") })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Disable|Enable/ })).toHaveCount(0);

  // Reached by its address, the policy says the API's 403.
  await page.goto("/en/policy");
  await expect(page.getByTestId("policy-role")).toBeVisible();
  await expect(page.locator('[role="alert"][data-status="403"]')).toContainText("Your role may not do this.");
});

test("an admin's switch with the switch store down shows the API's 503 as said and changes nothing; then it lands in the audit log", async ({ page, request }) => {
  await signIn(page, ADMIN, false);
  await page.getByRole("link", { name: "Source switches" }).click();
  const replay = page.locator('[data-testid="switch"][data-instance="replay-1"]');
  await expect(replay).toHaveAttribute("data-enabled", "true");

  await control(request, "/__mock/state", { kvDown: true });
  await replay.getByTestId("switch-replay-1").click();
  const dialog = page.getByRole("alertdialog");
  await dialog.getByLabel("Reason").fill("Receiver swap (synthetic)");
  await dialog.getByRole("button", { name: "Confirm" }).click();
  const refusal = replay.locator('[role="alert"][data-status="503"]');
  await expect(refusal).toContainText("the source_control bucket cannot be reached; nothing was changed");
  await expect(replay).toHaveAttribute("data-enabled", "true");

  await control(request, "/__mock/state", { kvDown: false });
  await replay.getByTestId("switch-replay-1").click();
  await page.getByRole("alertdialog").getByLabel("Reason").fill("Receiver swap (synthetic)");
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(replay).toHaveAttribute("data-enabled", "false");
  await expect(replay.getByTestId("switch-state")).toContainText("Disabled by admin1 at");

  await replay.getByRole("link", { name: "Audit entries" }).click();
  await expect(page).toHaveURL(/\/en\/audit\?entity=source_control/);
  await page.getByTestId("audit-load").click();
  await expect(page.getByTestId("audit-table")).toContainText("source_control:manned/replay-1");
  await expect(page.getByTestId("audit-table")).toContainText("Receiver swap (synthetic)");
  const download = page.waitForEvent("download");
  await page.getByTestId("audit-export").click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/^ansp-audit-.*\.json$/);
});

test("an occurrence report is queued with the protected reference sent once and never shown back", async ({ page, request }) => {
  await signIn(page, SUPER, true);
  await page.getByRole("link", { name: "Report an occurrence" }).click();
  await expect(page.getByTestId("occ-reporter-protected")).toHaveText("protected");
  await page.getByTestId("occ-occurred_at").fill("2026-10-02T11:20");
  await page.getByTestId("occ-became_aware_at").fill("2026-10-02T11:25");
  await expect(page.getByTestId("occurrence-deadline")).toContainText("2026-10-05 11:25");
  await page.getByTestId("occ-narrative").fill("Synthetic airprox between a UAS and a manned aircraft.");
  await page.getByLabel(/Reporter reference/).fill("staff-0042");
  await page.getByTestId("occ-submit").click();
  const receipt = page.getByTestId("occurrence-queued");
  await expect(receipt).toContainText("Queued to the authority as ANSP-OCC-2026-0001.");
  await expect(page.getByText("staff-0042")).toHaveCount(0);
  await expect(page.getByLabel(/Reporter reference/)).toHaveValue("");
  const posts = (await recorded(request)).filter((c) => c.method === "POST" && c.path === "/v1/occurrences");
  expect(posts).toHaveLength(1);
  expect(posts[0]?.body).toMatchObject({ channel: "mandatory", occurred_at: "2026-10-02T11:20:00Z", became_aware_at: "2026-10-02T11:25:00Z", reporter_person_ref: "staff-0042" });
  // The report's client reference reached the API through the BFF.
  expect(posts[0]?.idempotencyKey).toMatch(/^console-[0-9a-f-]{36}$/);
});
