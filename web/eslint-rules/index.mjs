import noGeometryImport from "./no-geometry-import.mjs";
import noHardcodedString from "./no-hardcoded-string.mjs";
import noServerBusinessLogic from "./no-server-business-logic.mjs";

/** This repository's three web/ rules, registered as `ansp/...`. */
export default {
  meta: { name: "uspace-ansp-web" },
  rules: {
    "no-geometry-import": noGeometryImport,
    "no-hardcoded-string": noHardcodedString,
    "no-server-business-logic": noServerBusinessLogic,
  },
};
