// Screenshots of every page in ka and en against the fixture server, for
// a PR and for docs/screenshots/. Runs only with SCREENSHOT_DIR set (it
// asserts nothing beyond what the smoke run does):
//
//   SCREENSHOT_DIR=docs/screenshots pnpm e2e screenshots
import { expect, test, type Page } from "@playwright/test";

const DIR = process.env["SCREENSHOT_DIR"];
const SUPER = { username: "super1", password: "super1-test-password" };

test.skip(DIR === undefined || DIR === "", "SCREENSHOT_DIR is not set");

async function shot(page: Page, name: string) {
  // The fonts are loaded before the picture is taken (a condition, not a delay).
  await page.evaluate(async () => {
    await document.fonts.ready;
  });
  await page.screenshot({ path: `${DIR}/${name}.jpg`, type: "jpeg", quality: 70, fullPage: true });
}

test("every page in ka and en", async ({ page, request }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  expect((await request.post("/__mock/reset")).ok()).toBe(true);
  await page.goto("/ka/login");
  await page.locator("#login-user").fill(SUPER.username);
  await page.locator("#login-password").fill(SUPER.password);
  await page.getByTestId("login-submit").click();
  await expect(page.getByTestId("enrolment-qr")).toBeVisible();
  await shot(page, "ka-login-enrolment");
  await page.locator("#login-otp").fill("246810");
  await page.getByTestId("login-submit").click();
  await expect(page).toHaveURL(/\/ka\/restrictions$/);

  // One restriction planned and activated through the API, as the smoke run does.
  await page.goto("/en/restrictions/new");
  await page.getByTestId("vertices").fill("44.78, 41.70\n44.82, 41.70\n44.82, 41.73\n44.78, 41.73");
  await page.getByLabel("U-space airspace (ED-318 identifier)").fill("GEOTU01");
  await page.getByRole("textbox", { name: "Lower limit (m)", exact: true }).fill("0");
  await page.getByRole("textbox", { name: "Upper limit (m)", exact: true }).fill("1200");
  await page.getByLabel("Starts, UTC").fill("2026-10-05T12:00");
  await page.getByLabel("Ends, UTC").fill("2026-10-05T16:00");
  await page.getByRole("textbox", { name: "Reason", exact: true }).fill("Search and rescue operation (synthetic)");
  await shot(page, "en-editor");
  await page.getByRole("button", { name: "Plan", exact: true }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Plan and send" }).click();
  await expect(page).toHaveURL(/\/en\/restrictions\/[0-9A-Z]{26}$/);
  const id = new URL(page.url()).pathname.split("/").pop() ?? "";
  await page.getByTestId("act-activate").click();
  await shot(page, "en-activate-confirm");
  await page.getByRole("alertdialog").getByLabel("Reason").fill("Rescue helicopter on scene (synthetic)");
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByTestId("restriction-detail")).toHaveAttribute("data-state", "active");

  for (const lang of ["ka", "en"] as const) {
    await page.goto(`/${lang}/restrictions`);
    await expect(page.getByTestId("restrictions-table")).toBeVisible();
    await shot(page, `${lang}-restrictions`);
    await page.goto(`/${lang}/restrictions/${id}`);
    await expect(page.getByTestId("restriction-detail")).toBeVisible();
    await shot(page, `${lang}-detail`);
    await page.goto(`/${lang}/restrictions/new`);
    await expect(page.getByTestId("vertices")).toBeVisible();
    await shot(page, `${lang}-new`);
    await page.goto(`/${lang}/requests?id=01K6P0R0000000000000000001`);
    await expect(page.getByTestId("request")).toBeVisible();
    await shot(page, `${lang}-request`);
    await page.goto(`/${lang}/adapters`);
    await expect(page.getByTestId("adapters")).toBeVisible();
    await shot(page, `${lang}-adapters`);
  }
});

const ADMIN = { username: "admin1", password: "admin1-test-password" };

async function signInAs(page: Page, who: { username: string; password: string }) {
  await page.goto("/en/login");
  await page.locator("#login-user").fill(who.username);
  await page.locator("#login-password").fill(who.password);
  await page.getByTestId("login-submit").click();
  await page.locator("#login-otp").fill("246810");
  await page.getByTestId("login-submit").click();
  await expect(page).toHaveURL(/\/en\/restrictions$/);
}

test("the WP-12 pages in ka and en: the picture with a stale and a disabled aircraft, the inbox, sources, policy, audit, occurrence", async ({ page, request }) => {
  await page.setViewportSize({ width: 1440, height: 1200 });
  expect((await request.post("/__mock/reset")).ok()).toBe(true);
  const post = async (path: string, data: Record<string, unknown>) => expect((await request.post(path, { data })).ok()).toBe(true);
  // Synthetic traffic: one live and relevant, one stale, one whose adapter was switched off, one outside.
  await post("/__mock/adapter", { id: "sbs-1", state: "disabled", who: "admin1" });
  await post("/__mock/manned", { icao24: "4ca7b5", callsign: "TST123", lat: 41.716, lng: 44.79, alt_pressure_m: 1250, alt_wgs84_m: 1310, relevant: true });
  await post("/__mock/manned", { icao24: "4ca7c1", callsign: "TST456", lat: 41.705, lng: 44.81, alt_pressure_m: 900, relevant: true, captured_at: new Date(Date.now() - 40_000).toISOString() });
  await post("/__mock/manned", { icao24: "4ca7c1", state: "stale" });
  await post("/__mock/manned", { icao24: "4ca7d2", callsign: "TST789", lat: 41.725, lng: 44.8, alt_pressure_m: 2100, relevant: true, source_instance: "sbs-1" });
  await post("/__mock/manned", { icao24: "4ca7d2", state: "source_disabled" });
  await post("/__mock/manned", { icao24: "4ca7e3", callsign: "TST999", lat: 41.69, lng: 44.76, alt_pressure_m: 3500, relevant: false, track_deg: 45 });
  await post("/__mock/notice", { ack_id: "01K6P0N0000000000000000001", received_at: new Date(Date.now() - 120_000).toISOString() });
  await post("/__mock/escalate", { ack_id: "01K6P0N0000000000000000001" });
  await post("/__mock/notice", { ack_id: "01K6P0N0000000000000000002", kind: "intent_notice" });

  await signInAs(page, ADMIN);
  for (const lang of ["ka", "en"] as const) {
    await page.goto(`/${lang}/picture`);
    await expect(page.locator('[data-aircraft="4ca7d2"]')).toHaveAttribute("data-state", "source_disabled");
    await expect(page.locator('[data-aircraft="4ca7c1"]')).toHaveAttribute("data-state", "stale");
    await expect(page.getByTestId("layer-manned")).toHaveAttribute("data-idle", "true");
    await shot(page, `${lang}-picture`);
    await page.goto(`/${lang}/inbox`);
    await expect(page.getByTestId("inbox-group-escalated")).toBeVisible();
    await expect(page.getByTestId("layer-notices")).toHaveAttribute("data-idle", "true");
    await shot(page, `${lang}-inbox`);
    await page.goto(`/${lang}/sources`);
    await expect(page.getByTestId("switches")).toBeVisible();
    await shot(page, `${lang}-sources`);
    await page.goto(`/${lang}/policy`);
    await expect(page.getByTestId("policy-table")).toBeVisible();
    await shot(page, `${lang}-policy`);
  }
  await page.goto("/en/sources");
  const replay = page.locator('[data-testid="switch"][data-instance="replay-1"]');
  await replay.getByTestId("switch-replay-1").click();
  await page.getByRole("alertdialog").getByLabel("Reason").fill("Receiver swap (synthetic)");
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(replay).toHaveAttribute("data-enabled", "false");
  for (const lang of ["ka", "en"] as const) {
    await page.goto(`/${lang}/audit`);
    await page.getByTestId("audit-load").click();
    await expect(page.getByTestId("audit-table")).toBeVisible();
    await shot(page, `${lang}-audit`);
  }
});

test("the occurrence form in ka and en", async ({ page, request }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  expect((await request.post("/__mock/reset")).ok()).toBe(true);
  await page.goto("/en/login");
  await page.locator("#login-user").fill(SUPER.username);
  await page.locator("#login-password").fill(SUPER.password);
  await page.getByTestId("login-submit").click();
  await page.locator("#login-otp").fill("246810");
  await page.getByTestId("login-submit").click();
  await expect(page).toHaveURL(/\/en\/restrictions$/);
  for (const lang of ["ka", "en"] as const) {
    await page.goto(`/${lang}/occurrences/new`);
    await page.getByTestId("occ-occurred_at").fill("2026-10-02T11:20");
    await page.getByTestId("occ-became_aware_at").fill("2026-10-02T11:25");
    await expect(page.getByTestId("occurrence-deadline")).toContainText("2026-10-05");
    await shot(page, `${lang}-occurrence`);
  }
});
