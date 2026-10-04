// The Playwright smoke run: `next start` behind test/mock-api.mjs, which
// stands in for Caddy (one origin; the API answered from fixtures, the
// restriction stream included). Run `pnpm build` first.
import { defineConfig, devices } from "@playwright/test";

const CI = process.env["CI"] !== undefined;
const WEB_PORT = "3100";
const ORIGIN_PORT = "3000";

export default defineConfig({
  testDir: "test/e2e",
  workers: 1,
  retries: 0,
  forbidOnly: CI,
  reporter: CI ? [["list"], ["github"]] : "list",
  use: {
    baseURL: `http://127.0.0.1:${ORIGIN_PORT}`,
    trace: "retain-on-failure",
    timezoneId: "UTC",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: `pnpm exec next start --port ${WEB_PORT} --hostname 127.0.0.1`,
      url: `http://127.0.0.1:${WEB_PORT}/healthz`,
      reuseExistingServer: !CI,
      env: {
        NEXT_TELEMETRY_DISABLED: "1",
        WEB_API_INTERNAL_URL: `http://127.0.0.1:${ORIGIN_PORT}`,
        // The fixture restrictions' area; test configuration, not a default.
        NEXT_PUBLIC_MAP_CENTER: "44.80,41.715",
        NEXT_PUBLIC_MAP_ZOOM: "12",
        // test/mock-api.mjs stands in for Caddy, one trusted hop that sets
        // X-Forwarded-Proto and -Host (the sign-in's Origin check).
        WEB_TRUSTED_PROXY_HOPS: "1",
        // Seals the MFA challenge cookie in this run only; a test value.
        WEB_MFA_CHALLENGE_SECRET: "playwright-run-only-challenge-seal-key",
      },
    },
    {
      command: "node test/mock-api.mjs",
      url: `http://127.0.0.1:${ORIGIN_PORT}/__mock/health`,
      reuseExistingServer: !CI,
      env: { MOCK_PORT: ORIGIN_PORT, MOCK_UPSTREAM: `http://127.0.0.1:${WEB_PORT}` },
    },
  ],
});
