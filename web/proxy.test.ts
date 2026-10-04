// The proxy's matcher: pages go through it, Next's assets, the BFF, the
// API paths, the basemap, /.well-known/, /healthz and /favicon.ico do
// not. A dot in the matcher is a literal dot, not any character.
import { describe, expect, it } from "vitest";
import { config } from "./proxy";

function matches(path: string): boolean {
  const [m] = config.matcher;
  if (m === undefined) throw new Error("no matcher");
  return new RegExp(`^${m}$`).test(path);
}

describe("proxy matcher", () => {
  it.each(["/", "/en", "/ka/restrictions", "/en/restrictions/new", "/en/requests"])("takes the page %s", (p) => {
    expect(matches(p)).toBe(true);
  });

  it.each(["/_next/static/x.js", "/_bff/api/v1/auth/me", "/v1/restrictions", "/uss/v1/x", "/basemap/style.json", "/.well-known/openid-configuration", "/healthz", "/favicon.ico"])(
    "leaves %s alone",
    (p) => {
      expect(matches(p)).toBe(false);
    },
  );

  it.each(["/xwell-known/a", "/faviconXico", "/favicon-ico"])("takes %s: the dot is literal", (p) => {
    expect(matches(p)).toBe(true);
  });

  it("holds the escapes in the string Next reads", () => {
    expect(config.matcher[0]).toContain("\\.well-known/");
    expect(config.matcher[0]).toContain("favicon\\.ico");
  });
});
