/**
 * Vulnerability: SQL Injection via GET parameter
 * Source: form input → /api/search?q=
 * Sink: string-concatenated SQL in app/api/search/route.ts
 * CWE-89, OWASP A03:2021
 * SAST Rules: Semgrep tainted-sql-string, SonarQube S2077, CodeQL js/sql-injection
 *
 * Try:
 *   alice
 *   ' OR '1'='1
 *   ' UNION SELECT id, name, value FROM secrets --
 */
"use client";

import { useState } from "react";

type Row = Record<string, string | number>;

export default function SqlInjectionPage() {
  const [q, setQ] = useState("");
  const [sql, setSql] = useState("");
  const [rows, setRows] = useState<Row[]>([]);
  const [error, setError] = useState("");

  async function search(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    const res = await fetch("/api/search?q=" + encodeURIComponent(q));
    const data = await res.json();
    setSql(data.sql ?? "");
    setRows(data.rows ?? []);
    if (data.error) setError(data.error);
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif" }}>
      <h1>SQL Injection Demo (User Search)</h1>
      <p>
        Backend builds the query with string concatenation:
        <code> &quot;SELECT ... WHERE username = &apos;&quot; + q + &quot;&apos;&quot;</code>
      </p>

      <form onSubmit={search} style={{ margin: "16px 0" }}>
        <input
          type="text"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="username"
          style={{ padding: 6, width: 360, border: "1px solid #888" }}
        />
        <button type="submit" style={{ marginLeft: 8, padding: "6px 12px" }}>
          Search
        </button>
      </form>

      <h3>Payloads to try</h3>
      <ul>
        <li><code>alice</code></li>
        <li><code>&apos; OR &apos;1&apos;=&apos;1</code> — returns all users</li>
        <li><code>&apos; UNION SELECT id, name, value FROM secrets --</code> — leak secrets table</li>
        <li><code>&apos; OR username LIKE &apos;%admin%</code> — find admin</li>
      </ul>

      {sql && (
        <>
          <h3>Executed SQL</h3>
          <pre style={{ background: "#111", color: "#0f0", padding: 12 }}>{sql}</pre>
        </>
      )}

      {error && (
        <pre style={{ background: "#400", color: "#fbb", padding: 12 }}>{error}</pre>
      )}

      {rows.length > 0 && (
        <>
          <h3>Results ({rows.length})</h3>
          <table border={1} cellPadding={6} style={{ borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {Object.keys(rows[0]).map((k) => (
                  <th key={k}>{k}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i}>
                  {Object.keys(rows[0]).map((k) => (
                    <td key={k}>{String(r[k] ?? "")}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
