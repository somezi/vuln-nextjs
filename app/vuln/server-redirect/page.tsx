/**
 * Vulnerability: Server-side Open Redirect
 * Source: link href / form GET → /api/redirect?to=
 * Sink: NextResponse.redirect() inside app/api/redirect/route.ts
 * CWE-601 · OWASP A01:2021
 */
"use client";

import { useState } from "react";

const payloads = [
  { p: "/vuln", note: "内部 — 無害" },
  { p: "//example.com/", note: "プロトコル相対 → 外部ドメインへ" },
  { p: "https://example.com/?next=login", note: "絶対URL (外部)" },
  {
    p: "https://attacker.example.com/oauth/callback?code=stolen",
    note: "OAuth/SSOコールバック乗っ取りシナリオ",
  },
];

export default function ServerRedirectPage() {
  const [to, setTo] = useState("/vuln");
  const url = "/api/redirect?to=" + encodeURIComponent(to);

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif" }}>
      <h1>サーバサイドオープンリダイレクトデモ</h1>
      <p>
        サーバルート <code>/api/redirect</code> は <code>?to=</code> の値で
        そのまま 302 を返す。allow-list も same-origin チェックもない。
        プロトコル相対ペイロードは現在のスキームを引き継いで
        攻撃者のドメインに着地する。
      </p>

      <form
        onSubmit={(e) => e.preventDefault()}
        style={{ margin: "16px 0", display: "flex", gap: 8, flexWrap: "wrap" }}
      >
        <input
          type="text"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          placeholder="リダイレクト先"
          style={{ padding: 6, width: 480, border: "1px solid #888" }}
        />
        <a href={url} style={{ padding: "6px 12px", border: "1px solid #888" }}>
          続行 →
        </a>
      </form>

      <h3>ペイロード例 (クリックで入力欄に反映)</h3>
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

      <h3>生成されるリンク</h3>
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
