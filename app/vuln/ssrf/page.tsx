/**
 * Vulnerability: SSRF (Server-Side Request Forgery)
 * Source: form input → GET /api/fetch?url=
 * Sink: fetch(url) inside app/api/fetch/route.ts
 * CWE-918 · OWASP A10:2021
 */
"use client";

import { useState } from "react";

type Result = {
  requestedUrl?: string;
  status?: number;
  headers?: Record<string, string>;
  body?: string;
  truncated?: boolean;
  error?: string;
};

const payloads = [
  { p: "https://example.com/", note: "外部 — 動作確認用 (無害)" },
  {
    p: "http://localhost:3000/api/comments",
    note: "同一サーバへループバック (内部API呼び出し)",
  },
  {
    p: "http://169.254.169.254/latest/meta-data/",
    note: "AWS インスタンスメタデータ (EC2で動作。Vercel/Lambdaは挙動が異なる)",
  },
  {
    p: "http://metadata.google.internal/computeMetadata/v1/",
    note: "GCP メタデータエンドポイント",
  },
  {
    p: "http://127.0.0.1:6379/",
    note: "Redis ポート — バナー取得 / 認証なしアクセス",
  },
  {
    p: "http://[::1]:3000/api/comments",
    note: "IPv6 ローカルホスト — 単純な 127.0.0.1 ブロックを回避",
  },
];

export default function SsrfPage() {
  const [url, setUrl] = useState("https://example.com/");
  const [result, setResult] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);

  async function go(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch("/api/fetch?url=" + encodeURIComponent(url));
      const data: Result = await res.json();
      setResult(data);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif" }}>
      <h1>SSRF デモ</h1>
      <p>
        サーバは送信されたURLをそのまま fetch してレスポンスを返す。
        スキーム/ホスト/IPのフィルタリングは一切ない。内部アドレス、
        クラウドメタデータエンドポイント、ポートスキャン対象などを試せる。
      </p>

      <form onSubmit={go} style={{ margin: "16px 0" }}>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="URL"
          style={{ padding: 6, width: 560, border: "1px solid #888" }}
        />
        <button
          type="submit"
          disabled={loading}
          style={{ marginLeft: 8, padding: "6px 12px" }}
        >
          {loading ? "実行中…" : "実行"}
        </button>
      </form>

      <h3>ペイロード例 (クリックで入力欄に反映)</h3>
      <ul style={{ listStyle: "none", padding: 0 }}>
        {payloads.map(({ p, note }) => (
          <li key={p} style={{ margin: "4px 0" }}>
            <button
              type="button"
              onClick={() => setUrl(p)}
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

      {result && (
        <>
          {result.error ? (
            <>
              <h3>エラー</h3>
              <pre style={{ background: "#400", color: "#fbb", padding: 12 }}>
                {result.error}
              </pre>
            </>
          ) : (
            <>
              <h3>
                ステータス: {result.status}
                {result.truncated && " (本文は省略)"}
              </h3>
              <h4>レスポンスヘッダ</h4>
              <pre
                style={{
                  background: "#111",
                  color: "#0f0",
                  padding: 12,
                  maxHeight: 200,
                  overflow: "auto",
                }}
              >
                {JSON.stringify(result.headers, null, 2)}
              </pre>
              <h4>レスポンスボディ</h4>
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
                {result.body}
              </pre>
            </>
          )}
        </>
      )}
    </div>
  );
}
