// The project rules: each fails its fixture and passes its twin that
// differs in one thing (E-01), first through RuleTester, then through the
// project's whole ESLint configuration on the files in fixtures/.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ESLint, RuleTester } from "eslint";
import tseslint from "typescript-eslint";
import { describe, expect, it } from "vitest";
import { schemaComponentNames } from "./components.mjs";
import noGeometryImport from "./no-geometry-import.mjs";
import noHardcodedString from "./no-hardcoded-string.mjs";
import noServerBusinessLogic from "./no-server-business-logic.mjs";

RuleTester.describe = describe;
RuleTester.it = it;
RuleTester.itOnly = it.only;

const tester = new RuleTester({
  languageOptions: {
    parser: tseslint.parser,
    ecmaVersion: 2024,
    sourceType: "module",
    parserOptions: { ecmaFeatures: { jsx: true } },
  },
});

tester.run("no-geometry-import", noGeometryImport, {
  valid: [
    { code: `import { RestrictionLayer } from "@rootxkit/uspace-ui/layers";`, filename: "app/[locale]/page.tsx" },
    { code: `import maplibregl from "maplibre-gl";`, filename: "src/map/x.ts" },
    { code: `import { encode } from "uqr";`, filename: "src/console/x.ts" },
    { code: `import { x } from "./geodesy-notes";`, filename: "src/x.ts" },
  ],
  invalid: [
    {
      code: `import booleanPointInPolygon from "@turf/boolean-point-in-polygon";`,
      filename: "app/[locale]/page.tsx",
      errors: [{ messageId: "forbidden" }],
    },
    { code: `import circle from "@turf/circle";`, filename: "src/x.ts", errors: [{ messageId: "forbidden" }] },
    { code: `import proj4 from "proj4";`, filename: "src/x.ts", errors: [{ messageId: "forbidden" }] },
    { code: `import { latLngToCell } from "h3-js";`, filename: "src/x.ts", errors: [{ messageId: "forbidden" }] },
    { code: `import type { Feature } from "geojson";`, filename: "src/x.ts", errors: [{ messageId: "forbidden" }] },
    { code: `import x from "@mapbox/geojson-area";`, filename: "src/x.ts", errors: [{ messageId: "forbidden" }] },
    { code: `import geolib from "geolib";`, filename: "src/x.ts", errors: [{ messageId: "forbidden" }] },
    { code: `import CheapRuler from "cheap-ruler";`, filename: "src/x.ts", errors: [{ messageId: "forbidden" }] },
    { code: `import x from "node-geodesy";`, filename: "src/x.ts", errors: [{ messageId: "forbidden" }] },
    { code: `const t = await import("@turf/area");`, filename: "src/x.ts", errors: [{ messageId: "forbidden" }] },
    { code: `const t = require("geolib");`, filename: "src/x.ts", errors: [{ messageId: "forbidden" }] },
  ],
});

tester.run("no-hardcoded-string", noHardcodedString, {
  valid: [
    { code: `const X = () => <p aria-label={t("k")}>{t("k")}</p>;`, filename: "src/x.tsx" },
    { code: `const X = () => <p>{t("k")} · {n} / 2 — <img alt="" /></p>;`, filename: "src/x.tsx" },
    { code: `const X = () => <code data-testid="state">{v}</code>;`, filename: "src/x.tsx" },
    { code: `const X = () => <input type="text" name="reason_text" />;`, filename: "src/x.tsx" },
  ],
  invalid: [
    { code: `const X = () => <p>No restrictions</p>;`, filename: "src/x.tsx", errors: [{ messageId: "text" }] },
    { code: `const X = () => <p>შეზღუდვა</p>;`, filename: "src/x.tsx", errors: [{ messageId: "text" }] },
    { code: `const X = () => <nav aria-label="Main" />;`, filename: "src/x.tsx", errors: [{ messageId: "attr" }] },
    { code: `const X = () => <input placeholder={"Reason"} />;`, filename: "src/x.tsx", errors: [{ messageId: "attr" }] },
    { code: "const X = () => <abbr title={`Upper limit`} />;", filename: "src/x.tsx", errors: [{ messageId: "attr" }] },
  ],
});

tester.run("no-server-business-logic", noServerBusinessLogic, {
  valid: [
    {
      code: `import { bff } from "@/src/bff/handlers"; import type { NextRequest } from "next/server";`,
      filename: "app/%5Fbff/login/route.ts",
    },
    {
      code: `import { bffHandlers } from "@rootxkit/uspace-ui/auth/server"; import { NextResponse } from "next/server";`,
      filename: "src/bff/handlers.ts",
    },
    { code: `import { readFileSync } from "node:fs";`, filename: "src/branding.ts" },
    { code: `export default function Page() { return null; }`, filename: "app/[locale]/page.tsx" },
  ],
  invalid: [
    {
      code: `export function GET() { return new Response("ok"); }`,
      filename: "app/api/zones/route.ts",
      errors: [{ messageId: "route" }],
    },
    {
      code: `export function GET() { return new Response("ok"); }`,
      filename: "app/[locale]/healthz/route.ts",
      errors: [{ messageId: "route" }],
    },
    {
      code: `import { Pool } from "pg";`,
      filename: "app/%5Fbff/login/route.ts",
      errors: [{ messageId: "forbidden" }],
    },
    {
      code: `import { branding } from "@/src/branding";`,
      filename: "app/_bff/logout/route.ts",
      errors: [{ messageId: "forbidden" }],
    },
    {
      code: `import { connect } from "nats";`,
      filename: "src/bff/handlers.ts",
      errors: [{ messageId: "forbidden" }],
    },
  ],
});

const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("the schema component names", () => {
  it("are read from the generated file", () => {
    const names = schemaComponentNames(readFileSync(path.join(webRoot, "src/api/generated/types.gen.ts"), "utf8"));
    expect(names).toContain("Restriction");
    expect(names).toContain("Problem");
    expect(names).toContain("RestrictionStateMessage");
    expect(names.length).toBeGreaterThan(50);
  });

  it("are none for a file without components.schemas", () => {
    expect(schemaComponentNames("export interface paths {}\n")).toEqual([]);
  });
});

describe("the project configuration on the fixtures", () => {
  // ignore: false lints the fixtures the configuration otherwise skips.
  const eslint = new ESLint({ cwd: webRoot, ignore: false });

  async function ruleIds(file: string): Promise<string[]> {
    const [result] = await eslint.lintFiles([path.join(webRoot, "eslint-rules/fixtures", file)]);
    return (result?.messages ?? []).map((m) => m.ruleId ?? "fatal");
  }

  it("a page importing @turf/boolean-point-in-polygon fails no-geometry-import", async () => {
    expect(await ruleIds("app/[locale]/geometry/page.tsx")).toContain("ansp/no-geometry-import");
  });

  it("a page with a hard-coded label and text fails no-hardcoded-string", async () => {
    const ids = await ruleIds("app/[locale]/literal/page.tsx");
    expect(ids.filter((id) => id === "ansp/no-hardcoded-string")).toHaveLength(2);
  });

  it("a hand-written Restriction type fails no-hand-written-api-types", async () => {
    expect(await ruleIds("app/[locale]/shadow/page.tsx")).toContain("uspace-ui/no-hand-written-api-types");
  });

  it("a route.ts outside _bff fails no-server-business-logic", async () => {
    expect(await ruleIds("app/api/zones/route.ts")).toContain("ansp/no-server-business-logic");
  });

  it("a BFF route importing a database client fails no-server-business-logic", async () => {
    expect(await ruleIds("app/%5Fbff/login/route.ts")).toContain("ansp/no-server-business-logic");
  });

  it("the real BFF files pass", async () => {
    const results = await eslint.lintFiles([
      path.join(webRoot, "app/%5Fbff"),
      path.join(webRoot, "src/bff/handlers.ts"),
    ]);
    expect(results.length).toBe(4);
    expect(results.flatMap((r) => r.messages)).toEqual([]);
  });
}, 60_000);
