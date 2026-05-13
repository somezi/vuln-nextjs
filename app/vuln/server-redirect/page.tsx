/**
 * Vulnerability: Server-side Open Redirect
 * Source: link href / form GET → /api/redirect?to=
 * Sink: NextResponse.redirect() inside app/api/redirect/route.ts
 * CWE-601 · OWASP A01:2021
 */
"use client";

import { useState } from "react";

const payloads = [
  { p: "/vuln", note: "internal — benign" },
  { p: "//example.com/", note: "protocol-relative → external domain" },
  { p: "https://example.com/?next=login", note: "absolute external URL" },
  {
    p: "https://attacker.example.com/oauth/callback?code=stolen",
    note: "OAuth/SSO callback hijack scenario",
  },
];

export default function ServerRedirectPage() {
  const [to, setTo] = useState("/vuln");
  const url = "/api/redirect?to=" + encodeURIComponent(to);

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif" }}>
      <h1>Server-side Open Redirect Demo</h1>
      <p>
        The server route <code>/api/redirect</code> issues a 302 to whatever{" "}
        <code>?to=</code> says — no allow-list, no same-origin check.
        Protocol-relative payloads inherit the current scheme and land on
        the attacker&apos;s domain.
      </p>

      <form
        onSubmit={(e) => e.preventDefault()}
        style={{ margin: "16px 0", display: "flex", gap: 8, flexWrap: "wrap" }}
      >
        <input
          type="text"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          placeholder="destination"
          style={{ padding: 6, width: 480, border: "1px solid #888" }}
        />
        <a href={url} style={{ padding: "6px 12px", border: "1px solid #888" }}>
          Continue →
        </a>
      </form>

      <h3>Payloads to try (click to fill)</h3>
      <ul style={{ listStyle: "none", padding: 0 }}>
        {payloads.map(({ p, note }) => (
          <li key={p} style={{ margin: "4px 0" }}>
            <button
              type="button"
              onClick={() => setTo(p)}
              style={{
                fontFamily: "monospace",
                padding: "4px 8px",
                border: "1px solid #888",
                background: "transparent",
                color: "inherit",
                cursor: "pointer",
                marginRight: 8,
              }}
            >
              {p}
            </button>
            <span style={{ color: "#888" }}>— {note}</span>
          </li>
        ))}
      </ul>

      <h3>Generated link</h3>
      <pre
        style={{
          background: "#111",
          color: "#0f0",
          padding: 12,
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
        }}
      >
        {url}
      </pre>
    </div>
  );
}
