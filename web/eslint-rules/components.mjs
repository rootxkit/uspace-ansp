// The schema component names of the generated API types, for the kit's
// no-hand-written-api-types rule: a hand-written `type Restriction` or
// `interface Problem` anywhere in web/ shadows a generated one and fails
// lint. Read from src/api/generated/types.gen.ts, the one source of the
// names (uspace-ui-gen-api over ../api/openapi.yaml).
import { readFileSync } from "node:fs";

/** The member names of `components.schemas` in a generated file's text. */
export function schemaComponentNames(text) {
  const start = text.indexOf("\n    schemas: {\n");
  if (start < 0) return [];
  const names = [];
  const lines = text.slice(start + "\n    schemas: {\n".length).split("\n");
  for (const line of lines) {
    if (line.startsWith("    }")) break;
    const m = /^ {8}"?([A-Za-z_][A-Za-z0-9_]*)"?\??: /.exec(line);
    if (m !== null && m[1] !== undefined) names.push(m[1]);
  }
  return names;
}

/** The names in the generated file at `url`; empty when it is missing. */
export function componentNamesFrom(url) {
  try {
    return schemaComponentNames(readFileSync(url, "utf8"));
  } catch {
    return [];
  }
}
