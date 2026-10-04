import kit from "@rootxkit/uspace-ui/eslint";
import { componentNamesFrom } from "./eslint-rules/components.mjs";
import ansp from "./eslint-rules/index.mjs";

const componentNames = componentNamesFrom(new URL("./src/api/generated/types.gen.ts", import.meta.url));

export default [
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "next-env.d.ts",
      "test-results/**",
      "playwright-report/**",
      // Files that must fail the project rules (eslint-rules/rules.test.ts).
      "eslint-rules/fixtures/**",
    ],
  },
  ...kit,
  {
    name: "uspace-ansp/web",
    plugins: { ansp },
    rules: {
      "ansp/no-geometry-import": "error",
      "ansp/no-server-business-logic": "error",
      "ansp/no-hardcoded-string": "error",
      // The kit's route rule, told about the module that configures the
      // BFF; the project rule above is the stricter of the two.
      "uspace-ui/no-business-logic-in-routes": ["error", { allow: ["^@/src/bff/handlers$"] }],
      // No hand-written copy of a generated schema type, anywhere.
      "uspace-ui/no-hand-written-api-types": ["error", { componentNames }],
    },
  },
  {
    // Tests and the fixture server may hold literal text (assertions).
    files: ["**/*.test.ts", "test/**", "eslint-rules/*.mjs"],
    rules: { "ansp/no-hardcoded-string": "off" },
  },
];
