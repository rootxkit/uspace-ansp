// The users page in the browser, through the real BFF (`next start`)
// against test/mock-api.mjs: an administrator creates a watch supervisor,
// sees the initial password once, copies it, and the account appears in
// the list the API answers; the new account enrols its authenticator at
// its first sign-in. Resetting an account's MFA and disabling it are each
// confirmed first, and a cancelled dialog sends nothing. A role other
// than admin is not shown the page and the API answers it 403 on every
// account operation. Each state is checked with axe (WCAG 2.2 AA). Every
// wait is on a condition, never on time.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

// The mock's test accounts and code (test/mock-api.mjs), not credentials.
const ADMIN = { username: "admin1", password: "admin1-test-password" };
const VIEWER = { username: "viewer1", password: "viewer1-test-password" };
const SUPER = { username: "super1", password: "super1-test-password" };
const CODE = "246810";
// A test value for this run's fixture account, not a credential of anything.
const NEW = { username: "watch2", password: "watch2-run-only-initial" };

const AXE_SOURCE = readFileSync(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8");
const WCAG_22_AA = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

/** Runs axe on the page as it is and fails naming every WCAG 2.2 AA violation. */
async function axe(page: Page, what: string) {
  // The document's title is streamed with the metadata; wait for it, then check.
  await expect(page).toHaveTitle(/supervisor console/);
  if (!(await page.evaluate(() => "axe" in window))) await page.addScriptTag({ content: AXE_SOURCE });
  const violations = await page.evaluate(async (tags) => {
    const w = window as unknown as { axe: { run(ctx: Document, opts: unknown): Promise<{ violations: { id: string; help: string; nodes: { target: string[] }[] }[] }> } };
    const r = await w.axe.run(document, { runOnly: { type: "tag", values: tags } });
    return r.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(" ")).join(", ")})`);
  }, WCAG_22_AA);
  expect(violations, what).toEqual([]);
}

/** Signs in; `enrols` says the account is shown its enrolment first. */
async function signIn(page: Page, who: { username: string; password: string }, enrols = false) {
  await page.goto("/en/login");
  await page.getByLabel("Username").fill(who.username);
  await page.getByLabel("Password").fill(who.password);
  await page.getByTestId("login-submit").click();
  if (enrols) await expect(page.getByTestId("enrolment-qr")).toBeVisible();
  else await expect(page.getByTestId("enrolment-qr")).toHaveCount(0);
  await page.getByLabel(/Code from your authenticator/).fill(CODE);
  await page.getByTestId("login-submit").click();
  await expect(page).toHaveURL(/\/en\/overview$/);
}

/** The status of a call through the BFF from the page (its cookies, same origin, the CSRF pair on a POST). */
async function bffStatus(page: Page, path: string, method = "GET", body?: unknown): Promise<number> {
  return page.evaluate(
    async ([p, m, b]) => {
      const csrf = /(?:^|; )uspace_csrf=([^;]*)/.exec(document.cookie)?.[1] ?? "";
      const init: RequestInit = { method: m, headers: { "X-CSRF-Token": decodeURIComponent(csrf), "Content-Type": "application/json" } };
      if (b !== undefined) init.body = JSON.stringify(b);
      return (await fetch(`/_bff/api${p}`, init)).status;
    },
    [path, method, body] as const,
  );
}

async function requests(request: APIRequestContext): Promise<{ method: string; path: string; keys: string[]; body?: unknown }[]> {
  const r = await request.get("/__mock/requests");
  return (await r.json()) as { method: string; path: string; keys: string[]; body?: unknown }[];
}

async function openUsers(page: Page) {
  const nav = page.getByRole("navigation", { name: "Main navigation" });
  await nav.getByRole("link", { name: "Users" }).click();
  await expect(page).toHaveURL(/\/en\/users$/);
  await expect(page.getByRole("heading", { level: 1, name: "Users" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Users" })).toHaveAttribute("aria-current", "page");
}

const row = (page: Page, username: string) => page.locator(`[data-testid="user-row"][data-user="${username}"]`);

test.beforeEach(async ({ request }) => {
  expect((await request.post("/__mock/reset")).ok()).toBe(true);
});

test("an admin creates a watch supervisor, sees its password once, and the account appears and enrols at its first sign-in", async ({ page, request, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await signIn(page, ADMIN);
  await openUsers(page);
  await expect(row(page, "admin1")).toHaveAttribute("data-role", "admin");
  await expect(row(page, "super1")).toHaveAttribute("data-role", "watch_supervisor");
  await expect(row(page, NEW.username)).toHaveCount(0);
  await axe(page, "the list and the form");

  // A refusal of the API is shown as it said it, field by field, and nothing is created.
  await page.getByTestId("user-username").fill(NEW.username);
  await page.getByTestId("user-password").fill("short");
  await page.getByTestId("user-create-submit").click();
  await expect(page.getByTestId("user-create").getByRole("alert")).toContainText("at least 12 characters");
  await expect(page.getByTestId("user-created")).toHaveCount(0);
  await axe(page, "the API's refusal");

  // Created: the role chosen, the password shown once with a copy button.
  await page.getByTestId("user-password").fill(NEW.password);
  await expect(page.getByTestId("user-role")).toHaveValue("watch_supervisor");
  await page.getByTestId("user-role").selectOption("watch_supervisor");
  await page.getByTestId("user-create-submit").click();
  const created = page.getByTestId("user-created");
  await expect(created).toContainText(`Account ${NEW.username} created as watch supervisor.`);
  await expect(page.getByTestId("user-created-password")).toHaveText(NEW.password);
  await expect(page.getByTestId("user-password")).toHaveValue("");
  await expect(page.getByTestId("user-username")).toHaveValue("");
  await page.getByTestId("user-created-copy").click();
  await expect(created.getByRole("status")).toHaveText("Copied to the clipboard.");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(NEW.password);
  await axe(page, "the one-time password");
  await expect(row(page, NEW.username)).toHaveAttribute("data-role", "watch_supervisor");
  await expect(row(page, NEW.username)).toHaveAttribute("data-status", "active");

  // The API received the account; the fixture never recorded its password.
  const posts = (await requests(request)).filter((r) => r.method === "POST" && r.path === "/v1/users");
  expect(posts.map((r) => r.keys)).toEqual([
    ["password", "role", "username"],
    ["password", "role", "username"],
  ]);
  expect(posts.every((r) => r.body === undefined)).toBe(true);

  // Dismissed, the password is gone from the page; read again, the account is the API's.
  await page.getByTestId("user-created-done").click();
  await expect(page.getByTestId("user-created")).toHaveCount(0);
  await expect(page.getByText(NEW.password)).toHaveCount(0);
  await page.reload();
  await expect(row(page, NEW.username)).toHaveAttribute("data-role", "watch_supervisor");
  await expect(page.getByText(NEW.password)).toHaveCount(0);

  // The new account enrols its authenticator at its first sign-in, as every account does.
  await context.clearCookies();
  await signIn(page, NEW, true);
  await expect(page.getByTestId("account")).toContainText(`${NEW.username} (watch supervisor)`);
  await expect(page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Users" })).toHaveCount(0);
});

test("reset MFA and disable are each confirmed first; a cancelled dialog sends nothing", async ({ page, request, context }) => {
  await signIn(page, ADMIN);
  await openUsers(page);
  const acts = async () => (await requests(request)).filter((r) => /^\/v1\/users\/[^/]+\/(reset-mfa|disable)$/.test(r.path));

  // Cancelled: nothing sent.
  await page.getByTestId("user-reset-mfa-viewer1").click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("Reset the authenticator of viewer1?");
  await axe(page, "the reset-MFA dialog");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toHaveCount(0);
  await page.getByTestId("user-disable-viewer1").click();
  await expect(dialog).toContainText("Disable viewer1?");
  await axe(page, "the disable dialog");
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  expect(await acts()).toEqual([]);

  // Confirmed: reset, then the account enrols again at its next sign-in.
  await page.getByTestId("user-reset-mfa-viewer1").click();
  await dialog.getByRole("button", { name: "Reset MFA" }).click();
  await expect(page.getByTestId("user-act-done")).toHaveText("The authenticator of viewer1 is reset; it enrols again at its next sign-in.");

  // Confirmed: disabled, its acts gone, said in words.
  await page.getByTestId("user-disable-viewer1").click();
  await dialog.getByRole("button", { name: "Disable the account" }).click();
  await expect(page.getByTestId("user-act-done")).toHaveText("viewer1 is disabled.");
  await expect(row(page, "viewer1")).toHaveAttribute("data-status", "disabled");
  await expect(row(page, "viewer1")).toContainText("Disabled");
  await expect(page.getByTestId("user-disable-viewer1")).toHaveCount(0);
  await expect(page.getByTestId("user-reset-mfa-viewer1")).toHaveCount(0);
  await axe(page, "a disabled account");
  expect((await acts()).map((r) => [r.method, r.path])).toEqual([
    ["POST", "/v1/users/01K6NZ8Q2W3E4R5T6Y7V8W9X1A/reset-mfa"],
    ["POST", "/v1/users/01K6NZ8Q2W3E4R5T6Y7V8W9X1A/disable"],
  ]);

  // The API's refusal is shown on the row: the last active admin is not disabled.
  await page.getByTestId("user-disable-admin1").click();
  await dialog.getByRole("button", { name: "Disable the account" }).click();
  await expect(row(page, "admin1").getByRole("alert")).toContainText("the last active admin cannot be disabled");
  await expect(row(page, "admin1")).toHaveAttribute("data-status", "active");

  // The reset account enrols again; the disabled one cannot sign in.
  await context.clearCookies();
  await signIn(page, SUPER, true);
  await context.clearCookies();
  await page.goto("/en/login");
  await page.getByLabel("Username").fill(VIEWER.username);
  await page.getByLabel("Password").fill(VIEWER.password);
  await page.getByTestId("login-submit").click();
  await expect(page.getByTestId("login-refusal")).toBeVisible();
  await expect(page.getByTestId("enrolment-qr")).toHaveCount(0);
});

for (const who of [VIEWER, SUPER]) {
  test(`${who.username} is not shown the users page and the API answers it 403`, async ({ page }) => {
    await signIn(page, who, who === SUPER);
    const nav = page.getByRole("navigation", { name: "Main navigation" });
    await expect(nav.getByRole("link", { name: "Audit log" })).toHaveCount(0);
    await expect(nav.getByRole("link", { name: "Users" })).toHaveCount(0);

    // Reached by its address: no form, no act, the API's 403 shown as it said it.
    await page.goto("/en/users");
    await expect(page.getByRole("heading", { level: 1, name: "Users" })).toBeVisible();
    await expect(page.getByTestId("users-role")).toBeVisible();
    await expect(page.locator('[role="alert"][data-status="403"]')).toBeVisible();
    await expect(page.getByTestId("user-create")).toHaveCount(0);
    await expect(page.getByTestId("users-table")).toHaveCount(0);
    await axe(page, "the refusal");

    // Every account operation through the BFF: forwarded, and refused by the API.
    expect(await bffStatus(page, "/v1/users")).toBe(403);
    expect(await bffStatus(page, "/v1/users", "POST", { username: "sneaky1", password: NEW.password, role: "admin" })).toBe(403);
    expect(await bffStatus(page, "/v1/users/01K6NZ8Q2W3E4R5T6Y7V8W9X2B/reset-mfa", "POST")).toBe(403);
    expect(await bffStatus(page, "/v1/users/01K6NZ8Q2W3E4R5T6Y7V8W9X2B/disable", "POST")).toBe(403);
    // Off the list: another method 405 and a neighbouring path 404, neither reaching the API.
    expect(await bffStatus(page, "/v1/users", "DELETE")).toBe(405);
    expect(await bffStatus(page, "/v1/users/01K6NZ8Q2W3E4R5T6Y7V8W9X2B")).toBe(404);
  });
}
