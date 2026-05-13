/**
 * Minimal EJS-style template renderer for demo purposes only.
 * Evaluates expressions inside `<%= ... %>` as JavaScript on the server.
 * Do not use outside of the SSTI vulnerability demo.
 */
import { createRequire } from "module";

const requireFn = createRequire(import.meta.url);

const defaultContext = {
  user: "guest",
  site: "vuln-nextjs",
};

export function renderTemplate(template: string): string {
  return template.replace(/<%=([\s\S]+?)%>/g, (_match, expr: string) => {
    // VULNERABLE: user-supplied template expressions are compiled and executed.
    // A safe renderer would lex/parse the expression and only allow lookups
    // into a known context, never arbitrary JavaScript.
    const fn = new Function(
      "ctx",
      "require",
      `with (ctx) { return (${expr}); }`,
    );
    const value = fn(defaultContext, requireFn);
    return stringify(value);
  });
}

function stringify(value: unknown): string {
  if (value === null || value === undefined) return String(value);
  if (typeof value === "object" || typeof value === "function") {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return Object.prototype.toString.call(value);
    }
  }
  return String(value);
}
