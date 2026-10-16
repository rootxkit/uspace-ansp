// The restriction lifecycle in the browser, through the real BFF (`next
// start`) against test/mock-api.mjs: sign in with MFA (the first sign-in
// shows the enrolment QR), plan a restriction on the editor, activate it,
// and see its delivery state change on the stream without a reload. Every
// request the page makes goes to this one origin (no third-party tile,
// font or script), and every act reached the API with its reason.
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { typeCircle, typeVertices } from "./outline";

// The mock's test account and code (test/mock-api.mjs), not credentials.
const SUPER = { username: "super1", password: "super1-test-password" };
const VIEWER = { username: "viewer1", password: "viewer1-test-password" };
const CODE = "246810";

interface Recorded {
  method: string;
  path: string;
  keys: string[];
  idempotencyKey?: string | null;
  authorization?: boolean;
  cookie?: boolean;
  body?: Record<string, unknown>;
  query?: Record<string, string>;
}

async function recorded(request: APIRequestContext): Promise<Recorded[]> {
  return (await (await request.get("/__mock/requests")).json()) as Recorded[];
}

/** Every request host the page asked for, from its first navigation on. */
function watchHosts(page: Page): Set<string> {
  const hosts = new Set<string>();
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.protocol === "data:" || u.protocol === "blob:") return;
    hosts.add(u.host);
  });
  return hosts;
}

async function signIn(page: Page, who: { username: string; password: string }, expectEnrolment: boolean) {
  await page.goto("/en/restrictions");
  await expect(page).toHaveURL(/\/en\/login$/);
  await page.getByLabel("Username").fill(who.username);
  await page.getByLabel("Password").fill(who.password);
  await page.getByTestId("login-submit").click();
  if (expectEnrolment) {
    await expect(page.getByTestId("enrolment-qr")).toBeVisible();
    await expect(page.getByTestId("enrolment")).toContainText("JBSWY3DPEHPK3PXP");
  } else {
    await expect(page.getByTestId("enrolment")).toHaveCount(0);
  }
  await page.getByLabel(/Code from your authenticator/).fill(CODE);
  await page.getByTestId("login-submit").click();
  // The page after sign-in is the overview; the flows below start on the list.
  await expect(page).toHaveURL(/\/en\/overview$/);
  await expect(page.getByTestId("status-bar")).toHaveAttribute("data-connection", "live");
  await page.getByRole("link", { name: "Restrictions", exact: true }).click();
  await expect(page).toHaveURL(/\/en\/restrictions$/);
}

test.beforeEach(async ({ request }) => {
  expect((await request.post("/__mock/reset")).ok()).toBe(true);
});

test("sign in with MFA, plan a restriction, activate it, see the delivery change on the stream", async ({ page, request }) => {
  const hosts = watchHosts(page);
  await signIn(page, SUPER, true);
  await expect(page.getByTestId("restrictions-none")).toContainText("No restrictions");
  await expect(page.getByTestId("alarms-none")).toBeVisible();
  await expect(page.getByTestId("account")).toContainText("super1 (watch supervisor)");

  // Plan: the area typed through the kit's outline fields, the rest
  // through the form.
  await page.getByTestId("plan-link").click();
  await expect(page).toHaveURL(/\/en\/restrictions\/new$/);
  await typeVertices(page, [
    [44.78, 41.7],
    [44.82, 41.7],
    [44.82, 41.73],
    [44.78, 41.73],
  ]);
  await expect(page.locator("[data-vertex-count]")).toHaveText("4 of at most 999 points");
  await page.getByLabel("U-space airspace (ED-318 identifier)").fill("GEOTU01");
  await page.getByRole("textbox", { name: "Lower limit (m)", exact: true }).fill("0");
  await page.getByRole("textbox", { name: "Upper limit (m)", exact: true }).fill("1200");
  await page.getByLabel("Starts, UTC").fill("2026-10-05T12:00");
  await page.getByLabel("Ends, UTC").fill("2026-10-05T16:00");
  await page.getByRole("textbox", { name: "Reason", exact: true }).fill("Search and rescue operation (synthetic)");
  await expect(page.getByTestId("agl-note")).toContainText("terrain_unavailable");
  await page.getByRole("button", { name: "Plan", exact: true }).click();
  const confirm = page.getByRole("alertdialog");
  await expect(confirm).toContainText("publishes it to the CISP as planned");
  await confirm.getByRole("button", { name: "Plan and send" }).click();

  await expect(page).toHaveURL(/\/en\/restrictions\/[0-9A-Z]{26}$/);
  const detail = page.getByTestId("restriction-detail");
  await expect(detail).toHaveAttribute("data-state", "planned");
  await expect(page.getByTestId("delivery-lines")).toContainText("CISP: v1 not yet published");
  await expect(page.getByTestId("delivery-lines")).toContainText("DSS: not written");
  const id = new URL(page.url()).pathname.split("/").pop() ?? "";

  // Activate, confirmed with a reason.
  await page.getByTestId("act-activate").click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("writes the F3548 constraint to the DSS");
  await dialog.getByLabel("Reason").fill("Rescue helicopter on scene (synthetic)");
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(detail).toHaveAttribute("data-state", "active");
  await expect(page.getByTestId("version")).toHaveText("v2");
  const lines = page.getByTestId("delivery-lines");
  await expect(lines).toContainText("CISP: v2 not yet published since");
  await expect(lines).toContainText("DSS: pending since");
  await expect(page.getByTestId("alarms")).toContainText("Active here, not yet published to the CISP");

  // The outbox delivers: the stream carries it, the page is not reloaded.
  const navigations: string[] = [];
  page.on("framenavigated", (f) => navigations.push(f.url()));
  expect((await request.post("/__mock/deliver", { data: { id } })).ok()).toBe(true);
  await expect(lines).toContainText("CISP: published v2 at");
  await expect(lines).toContainText("DSS: written (v2, DSS version 1)");
  await expect(lines).toContainText("USSPs: notified at");
  await expect(page.getByTestId("alarms")).toHaveCount(0);
  expect(navigations).toEqual([]);

  // The list shows the same, live.
  await page.getByRole("link", { name: "All restrictions" }).click();
  const row = page.locator(`tr[data-state="active"]`);
  await expect(row).toContainText("CISP: published v2 at");

  // What reached the API: the plan once with its client reference, the
  // activation with its reason, the stream with the session cookie.
  const calls = await recorded(request);
  const plans = calls.filter((c) => c.method === "POST" && c.path === "/v1/restrictions");
  expect(plans).toHaveLength(1);
  expect(plans[0]?.idempotencyKey).toMatch(/^console-[0-9a-f-]{36}$/);
  expect(plans[0]?.body).toMatchObject({
    uspace_airspace_id: "GEOTU01",
    geometry: { type: "Polygon", coordinates: [[[44.78, 41.7], [44.82, 41.7], [44.82, 41.73], [44.78, 41.73], [44.78, 41.7]]] },
    lower_m: 0,
    lower_ref: "AMSL",
    upper_m: 1200,
    upper_ref: "AMSL",
    starts_at: "2026-10-05T12:00:00Z",
    ends_at: "2026-10-05T16:00:00Z",
    radius_m: null,
  });
  const activations = calls.filter((c) => c.method === "POST" && c.path === `/v1/restrictions/${id}/activate`);
  expect(activations).toEqual([expect.objectContaining({ keys: ["reason"], authorization: true, body: { reason: "Rescue helicopter on scene (synthetic)" } })]);
  expect(calls.filter((c) => c.method === "WS").every((c) => c.cookie === true)).toBe(true);
  expect(calls.some((c) => c.method === "WS")).toBe(true);

  // One origin: no third-party tile, font or script request, ever.
  expect([...hosts]).toEqual(["127.0.0.1:3000"]);
});

test("a long window comes back as the chain the API proposes, planned only when ticked", async ({ page, request }) => {
  await signIn(page, SUPER, true);
  await page.getByTestId("plan-link").click();
  await typeVertices(page, [
    [44.78, 41.7],
    [44.82, 41.7],
    [44.8, 41.73],
  ]);
  await page.getByLabel("U-space airspace (ED-318 identifier)").fill("GEOTU01");
  await page.getByRole("textbox", { name: "Lower limit (m)", exact: true }).fill("0");
  await page.getByRole("textbox", { name: "Upper limit (m)", exact: true }).fill("600");
  await page.getByLabel("Starts, UTC").fill("2026-10-05T12:00");
  await page.getByLabel("Ends, UTC").fill("2026-10-07T12:00");
  await page.getByRole("textbox", { name: "Reason", exact: true }).fill("Exercise (synthetic)");
  await page.getByRole("button", { name: "Plan", exact: true }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Plan and send" }).click();
  await expect(page.getByTestId("chain-proposal")).toContainText("a chain of 2 re-issues");
  await expect(page).toHaveURL(/\/new$/);

  await page.getByLabel("Plan as a chain").check();
  await page.getByRole("button", { name: "Plan", exact: true }).click();
  await expect(page.getByRole("alertdialog")).toContainText("chain of linked re-issues");
  await page.getByRole("alertdialog").getByRole("button", { name: "Plan and send" }).click();
  await expect(page).toHaveURL(/\/en\/restrictions\/[0-9A-Z]{26}$/);

  const plans = (await recorded(request)).filter((c) => c.method === "POST" && c.path === "/v1/restrictions");
  expect(plans.map((c) => c.body?.["confirm_chain"] ?? false)).toEqual([false, true]);
  // A refused plan does not reuse its client reference for another body.
  expect(plans[0]?.idempotencyKey).not.toBe(plans[1]?.idempotencyKey);
});

test("cancelling the confirmation sends nothing", async ({ page, request }) => {
  await signIn(page, SUPER, true);
  await page.getByTestId("plan-link").click();
  await typeVertices(page, [
    [44.78, 41.7],
    [44.82, 41.7],
    [44.8, 41.73],
  ]);
  await page.getByLabel("U-space airspace (ED-318 identifier)").fill("GEOTU01");
  await page.getByRole("textbox", { name: "Lower limit (m)", exact: true }).fill("0");
  await page.getByRole("textbox", { name: "Upper limit (m)", exact: true }).fill("600");
  await page.getByLabel("Starts, UTC").fill("2026-10-05T12:00");
  await page.getByLabel("Ends, UTC").fill("2026-10-05T14:00");
  await page.getByRole("textbox", { name: "Reason", exact: true }).fill("Exercise (synthetic)");
  await page.getByRole("button", { name: "Plan", exact: true }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByText("not sent: the confirmation was cancelled")).toBeVisible();
  expect((await recorded(request)).filter((c) => c.method === "POST" && c.path === "/v1/restrictions")).toEqual([]);
});

// The kit's drawing tool with a circle (docs/PLAN.md section 15 row 53):
// the outline on the map is the one the API drew, and the plan sends the
// circle as its centre and radius, never the outline.
test("a circle is drawn from the API's outline and planned as its centre and radius", async ({ page, request }) => {
  await signIn(page, SUPER, true);
  await page.getByTestId("plan-link").click();
  await typeCircle(page, [44.8, 41.715], 1500);
  await expect(page.locator("[data-circle-outline]")).toHaveText("The circle on the map is the outline the system drew.");
  await expect(page.getByTestId("circle-outline-refused")).toHaveCount(0);
  const asked = (await recorded(request)).filter((c) => c.method === "GET" && c.path === "/v1/outlines/circle");
  expect(asked.at(-1)?.query).toEqual({ lat: "41.715", lng: "44.8", radius_m: "1500" });

  await page.getByLabel("U-space airspace (ED-318 identifier)").fill("GEOTU01");
  await page.getByRole("textbox", { name: "Lower limit (m)", exact: true }).fill("0");
  await page.getByRole("textbox", { name: "Upper limit (m)", exact: true }).fill("600");
  await page.getByLabel("Starts, UTC").fill("2026-10-05T12:00");
  await page.getByLabel("Ends, UTC").fill("2026-10-05T14:00");
  await page.getByRole("textbox", { name: "Reason", exact: true }).fill("Exercise (synthetic)");
  await page.getByRole("button", { name: "Plan", exact: true }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Plan and send" }).click();
  await expect(page).toHaveURL(/\/en\/restrictions\/[0-9A-Z]{26}$/);
  const plans = (await recorded(request)).filter((c) => c.method === "POST" && c.path === "/v1/restrictions");
  expect(plans).toHaveLength(1);
  expect(plans[0]?.body).toMatchObject({ geometry: { type: "Point", coordinates: [44.8, 41.715] }, radius_m: 1500 });
});

test("a circle the API will not draw shows its centre and says so", async ({ page, request }) => {
  await signIn(page, SUPER, true);
  await page.getByTestId("plan-link").click();
  await typeCircle(page, [44.8, 41.715], 2_000_000);
  await expect(page.getByTestId("circle-outline-refused")).toBeVisible();
  await expect(page.locator("[data-circle-outline]")).toHaveText("The system draws a circle's outline; until it has, the map shows its centre only.");
  const asked = (await recorded(request)).filter((c) => c.method === "GET" && c.path === "/v1/outlines/circle");
  expect(asked.at(-1)?.query).toEqual({ lat: "41.715", lng: "44.8", radius_m: "2000000" });
});

test("a viewer reads restrictions and adapters but is offered no act; disabled is not silent", async ({ page }) => {
  await signIn(page, VIEWER, false);
  await expect(page.getByTestId("account")).toContainText("viewer1 (viewer)");
  await page.getByRole("link", { name: "Plan a restriction" }).first().click();
  await expect(page.getByTestId("editor-role")).toBeVisible();

  await page.getByRole("link", { name: "Surveillance adapters" }).click();
  const disabled = page.locator('[data-adapter="sbs-1"]');
  await expect(disabled).toHaveAttribute("data-status", "disabled");
  await expect(disabled.getByTestId("adapter-status")).toContainText("Disabled by admin at");
  await expect(disabled.getByTestId("adapter-status")).toContainText("Receiver under maintenance (synthetic)");
  const silent = page.locator('[data-adapter="json-1"]');
  await expect(silent.getByTestId("adapter-status")).toContainText("Silent since");
  await expect(page.locator('[data-adapter="replay-1"]').getByTestId("adapter-status")).toContainText("Running; last frame");
});

test("a request is opened by its id, shown pre-filled on the map, and accepted with a reason", async ({ page, request }) => {
  await signIn(page, SUPER, true);
  await page.getByRole("link", { name: "Restriction requests" }).click();
  // A supervisor is listed the requests awaiting a decision.
  await expect(page.getByTestId("requests-no-list")).toHaveCount(0);
  await expect(page.locator('[data-testid="requests-pending"] [data-request="01K6P0R0000000000000000001"]')).toContainText("the authority (authority-01)");
  await page.getByTestId("request-id").fill("01K6P0R0000000000000000001");
  await page.getByTestId("request-open").click();
  const req = page.getByTestId("request");
  await expect(req).toHaveAttribute("data-state", "received");
  await expect(req).toContainText("Public event (synthetic example)");
  await expect(req).toContainText("0 m AMSL to 900 m AMSL");
  await page.getByTestId("request-accept").click();
  await page.getByRole("alertdialog").getByLabel("Reason").fill("Requested by the authority for the event (synthetic)");
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(req).toHaveAttribute("data-state", "accepted");
  await expect(page.getByTestId("requests-none-waiting")).toBeVisible();
  await page.getByTestId("request-restriction").click();
  await expect(page.getByTestId("restriction-detail")).toHaveAttribute("data-state", "planned");
  const accepts = (await recorded(request)).filter((c) => c.path.endsWith("/accept"));
  expect(accepts).toEqual([expect.objectContaining({ body: { zone_type: "PROHIBITED", reason: "Requested by the authority for the event (synthetic)" } })]);
});

test("a stale CIS projection says why nothing can be planned", async ({ page, request }) => {
  await signIn(page, SUPER, true);
  expect((await request.post("/__mock/state", { data: { cisStale: true } })).ok()).toBe(true);
  await page.reload();
  await expect(page.getByTestId("status-bar")).toContainText("400");
  await expect(page.getByTestId("list-cis")).toContainText("projection age 400 s");
});

test("signed in again: the next 2xx clears the signed-out notice and reads /me again", async ({ page, context }) => {
  await signIn(page, SUPER, true);
  const good = await context.cookies();
  await context.clearCookies();
  // A session cookie the API does not know (the session ended elsewhere).
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const payload = Buffer.from(JSON.stringify({ sub: "x", roles: ["watch_supervisor"], realm: "console", exp })).toString("base64url");
  await context.addCookies([{ name: "uspace_session", value: `e30.${payload}.sig`, url: "http://127.0.0.1:3000", httpOnly: true, sameSite: "Strict" }]);
  await page.goto("/en/restrictions");
  await expect(page.getByTestId("signed-out")).toContainText("Signed out");
  await expect(page.getByTestId("account")).toHaveCount(0);
  // Signed in again in another tab: the browser holds a live session.
  await context.clearCookies();
  await context.addCookies(good);
  // In-app navigation keeps the console mounted; its next call answers 2xx.
  await page.getByRole("link", { name: "Surveillance adapters" }).click();
  await expect(page).toHaveURL(/\/en\/adapters$/);
  await expect(page.getByTestId("signed-out")).toHaveCount(0);
  await expect(page.getByTestId("account")).toContainText("super1");
});

test("signed out: the stream's 4401 and the API's 401 say sign in again", async ({ page, context }) => {
  await signIn(page, SUPER, true);
  await context.clearCookies();
  // A session cookie the API does not know (the session ended elsewhere).
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const payload = Buffer.from(JSON.stringify({ sub: "x", roles: ["watch_supervisor"], realm: "console", exp })).toString("base64url");
  await context.addCookies([{ name: "uspace_session", value: `e30.${payload}.sig`, url: "http://127.0.0.1:3000", httpOnly: true, sameSite: "Strict" }]);
  await page.goto("/en/restrictions");
  await expect(page.getByTestId("signed-out")).toContainText("Signed out");
  await page.getByRole("link", { name: "Sign in again" }).click();
  await expect(page).toHaveURL(/\/en\/login$/);
});
