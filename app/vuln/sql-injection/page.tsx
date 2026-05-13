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
      <h1>SQLインジェクションデモ (ユーザー検索)</h1>
      <p>
        バックエンドは文字列連結でクエリを組み立てている:
        <code> &quot;SELECT ... WHERE username = &apos;&quot; + q + &quot;&apos;&quot;</code>
      </p>

      <form onSubmit={search} style={{ margin: "16px 0" }}>
        <input
          type="text"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="ユーザー名"
          style={{ padding: 6, width: 360, border: "1px solid #888" }}
        />
        <button type="submit" style={{ marginLeft: 8, padding: "6px 12px" }}>
          検索
        </button>
      </form>

      <h3>ペイロード例 (クリックで入力欄に反映)</h3>
      <ul style={{ listStyle: "none", padding: 0 }}>
        {[
          { p: "alice", note: "通常の検索" },
          { p: "' OR '1'='1", note: "全ユーザー取得" },
          { p: "' UNION SELECT id, name, value FROM secrets --", note: "secrets テーブル漏えい" },
          { p: "' OR username LIKE '%admin%", note: "admin を検索" },
        ].map(({ p, note }) => (
          <li key={p} style={{ margin: "4px 0" }}>
            <button
              type="button"
              onClick={() => setQ(p)}
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

      {sql && (
        <>
          <h3>実行されるSQL</h3>
          <pre style={{ background: "#111", color: "#0f0", padding: 12 }}>{sql}</pre>
        </>
      )}

      {error && (
        <pre style={{ background: "#400", color: "#fbb", padding: 12 }}>{error}</pre>
      )}

      {rows.length > 0 && (
        <>
          <h3>結果 ({rows.length})</h3>
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
