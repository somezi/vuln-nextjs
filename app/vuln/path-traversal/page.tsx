/**
 * Vulnerability: Path Traversal
 * Source: form input → GET /api/files?name=
 * Sink: fs.readFileSync(path.join(baseDir, name)) in app/api/files/route.ts
 * CWE-22 · OWASP A01:2021
 *
 * Payloads (use the buttons below):
 *   notes.txt                      — normal lookup
 *   .secrets/flag.txt              — hidden directory under baseDir
 *   ../package.json                — escape baseDir, read repo file
 *   ../../../../etc/hosts          — escape further, read OS file
 */
"use client";

import { useState } from "react";

const payloads = [
  { p: "notes.txt", note: "normal lookup" },
  { p: ".secrets/flag.txt", note: "hidden directory under baseDir" },
  { p: "../package.json", note: "escape baseDir → repo file" },
  { p: "../app/api/files/route.ts", note: "leak server source code" },
  { p: "../../../../../../etc/hosts", note: "escape further → OS file (Linux/macOS)" },
];

export default function PathTraversalPage() {
  const [name, setName] = useState("notes.txt");
  const [resolved, setResolved] = useState("");
  const [content, setContent] = useState("");
  const [error, setError] = useState("");

  async function read(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setContent("");
    setResolved("");
    const res = await fetch("/api/files?name=" + encodeURIComponent(name));
    const data = await res.json();
    setResolved(data.resolved ?? "");
    if (data.error) {
      setError(data.error);
      return;
    }
    setContent(data.content ?? "");
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif" }}>
      <h1>Path Traversal Demo</h1>
      <p>
        Backend joins the requested name onto a fixed base directory with{" "}
        <code>path.join(baseDir, name)</code> — no containment check. Use{" "}
        <code>..</code> segments to read files outside the intended scope.
      </p>

      <form onSubmit={read} style={{ margin: "16px 0" }}>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="file name"
          style={{ padding: 6, width: 480, border: "1px solid #888" }}
        />
        <button type="submit" style={{ marginLeft: 8, padding: "6px 12px" }}>
          Read
        </button>
      </form>

      <h3>Payloads to try (click to fill)</h3>
      <ul style={{ listStyle: "none", padding: 0 }}>
        {payloads.map(({ p, note }) => (
          <li key={p} style={{ margin: "4px 0" }}>
            <button
              type="button"
              onClick={() => setName(p)}
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

      {resolved && (
        <>
          <h3>Resolved path</h3>
          <pre style={{ background: "#111", color: "#0f0", padding: 12 }}>
            {resolved}
          </pre>
        </>
      )}

      {error && (
        <pre style={{ background: "#400", color: "#fbb", padding: 12 }}>
          {error}
        </pre>
      )}

      {content && (
        <>
          <h3>File content</h3>
          <pre
            style={{
              background: "#111",
              color: "#0f0",
              padding: 12,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              maxHeight: 400,
              overflow: "auto",
            }}
          >
            {content}
          </pre>
        </>
      )}
    </div>
  );
}
