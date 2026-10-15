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

test("a viewer's overview has no accounts tile and the API refuses it the summary", async ({ page }) => {
  await signIn(page, VIEWER);
  await expect(page.getByTestId("kpi-active")).toHaveAttribute("data-value", "0");
  await expect(page.getByTestId("kpi-users")).toHaveCount(0);
  expect(await bffStatus(page, "/v1/users/summary")).toBe(403);
});
