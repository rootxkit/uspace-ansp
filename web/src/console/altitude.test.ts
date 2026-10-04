// CLAUDE.md rule 9 and the WP-12 brief: the browser never does
// arithmetic on an altitude. Pressure altitude and WGS84 height are shown
// as sent, each with its datum, never summed, differenced, scaled or
// converted. This test reads every source file of app/ and src/ (tests
// excepted) and fails on an altitude name (alt_..., altPressureM,
// altWgs84M, ...) that is an operand of + - * / % or of a compound
// assignment; the checker is shown to find each shape (E-01).
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) return name === "generated" ? [] : sources(p);
    return /\.(ts|tsx|mjs)$/.test(name) && !/\.test\.ts$/.test(name) ? [p] : [];
  });
}

/** Comments and string contents blanked, so text about altitudes is not code. */
function codeOnly(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1")
    .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\\n]|\\.)*'/g, "''")
    .replace(/`(?:[^`\\]|\\.)*`/g, "``");
}

/** An altitude name: alt_<...> or alt<Upper>... (altPressureM, altWgs84M, altAmslM). */
const ALT = String.raw`\b(?:alt_[A-Za-z0-9_]+|alt[A-Z][A-Za-z0-9_]*)\b`;
/** A member access or optional chain may sit between the name and the operator. */
const OPERATOR = String.raw`(?:[+\-*/%]=?(?![=>])|\*\*)`;
const AFTER = new RegExp(String.raw`${ALT}(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*\s*!?\s*(?:\?\?\s*[^)\n]*)?\)?\s*${OPERATOR}(?![+\-])`);
const BEFORE = new RegExp(String.raw`(?<![+\-])${OPERATOR}\s*\(?\s*(?:[A-Za-z_$][\w$]*\s*\??\.\s*)*${ALT}`);

/** The lines of `src` where an altitude is an arithmetic operand. */
export function altitudeArithmetic(src: string): string[] {
  return codeOnly(src)
    .split("\n")
    .filter((line) => AFTER.test(line) || BEFORE.test(line))
    .map((line) => line.trim());
}

describe("no altitude arithmetic in the browser", () => {
  it("finds none in app/ and src/", () => {
    const files = [...sources(path.join(web, "app")), ...sources(path.join(web, "src"))];
    expect(files.length).toBeGreaterThan(20);
    const found = files.flatMap((f) => altitudeArithmetic(readFileSync(f, "utf8")).map((l) => `${path.relative(web, f)}: ${l}`));
    expect(found).toEqual([]);
  });

  it("finds each arithmetic shape", () => {
    expect(altitudeArithmetic("const v = a.alt_pressure_m + 30;")).toHaveLength(1);
    expect(altitudeArithmetic("const v = 30 - a.altWgs84M;")).toHaveLength(1);
    expect(altitudeArithmetic("const v = x.altPressureM * 3.28084;")).toHaveLength(1);
    expect(altitudeArithmetic("const v = (a.alt_wgs84_m ?? 0) / 2;")).toHaveLength(1);
    expect(altitudeArithmetic("total += track.altPressureM;")).toHaveLength(1);
    expect(altitudeArithmetic("const d = a.altWgs84M - a.altPressureM;")).toHaveLength(1);
    expect(altitudeArithmetic("const v = alt_m % 100;")).toHaveLength(1);
  });

  it("passes copies, comparisons and text", () => {
    expect(altitudeArithmetic("const v = a.alt_pressure_m ?? null;")).toEqual([]);
    expect(altitudeArithmetic("if (a.altPressureM === null) return;")).toEqual([]);
    expect(altitudeArithmetic("fmtAltitude(a.altWgs84M, 'WGS84', lang)")).toEqual([]);
    expect(altitudeArithmetic("// alt_pressure_m - never summed")).toEqual([]);
    expect(altitudeArithmetic('const k = "alt_pressure_m + 1";')).toEqual([]);
    expect(altitudeArithmetic("const f = (a) => a.altPressureM;")).toEqual([]);
  });
});
