// CLAUDE.md rule 12: every user-facing string goes through i18n (ka, en)
// from day one. A JSX text node that holds a letter, or an accessible
// label (aria-label, title, alt, placeholder, label) given as a string
// literal holding a letter, is a hard-coded display string: it belongs
// in src/i18n/{ka,en}.json and reaches the page through `t(...)`.
// Punctuation, numbers and an empty alt are not display text.
const LETTER = /\p{L}/u;
export const LABEL_ATTRS = new Set(["aria-label", "aria-description", "title", "alt", "placeholder", "label"]);

function attrText(value) {
  if (value === null || value === undefined) return null;
  if (value.type === "Literal" && typeof value.value === "string") return value.value;
  if (value.type === "JSXExpressionContainer") {
    const e = value.expression;
    if (e.type === "Literal" && typeof e.value === "string") return e.value;
    if (e.type === "TemplateLiteral" && e.expressions.length === 0) return e.quasis.map((q) => q.value.cooked).join("");
  }
  return null;
}

/** @type {import("eslint").Rule.RuleModule} */
export default {
  meta: {
    type: "problem",
    docs: { description: "Forbids display strings outside the ka and en catalogues (CLAUDE.md rule 12)." },
    schema: [],
    messages: {
      text: "Hard-coded display text {{text}}: put it in src/i18n/ka.json and en.json and render t(key).",
      attr: "Hard-coded {{name}} {{text}}: put it in src/i18n/ka.json and en.json and pass t(key).",
    },
  },
  create(context) {
    return {
      JSXText(node) {
        if (LETTER.test(node.value)) {
          context.report({ node, messageId: "text", data: { text: JSON.stringify(node.value.trim()) } });
        }
      },
      JSXAttribute(node) {
        if (node.name.type !== "JSXIdentifier" || !LABEL_ATTRS.has(node.name.name)) return;
        const text = attrText(node.value);
        if (text !== null && LETTER.test(text)) {
          context.report({ node, messageId: "attr", data: { name: node.name.name, text: JSON.stringify(text) } });
        }
      },
    };
  },
};
