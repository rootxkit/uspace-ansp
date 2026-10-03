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
