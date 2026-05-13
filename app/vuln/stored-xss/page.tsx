/**
 * Vulnerability: Stored XSS (server persisted, client innerHTML)
 * Source: POST /api/comments → server stores raw HTML/JS
 * Sink: dangerouslySetInnerHTML on every viewer's page
 * CWE-79, OWASP A03:2021
 * SAST Rules: Semgrep react-dangerously-set-inner-html, ESLint react/no-danger
 *
 * Payloads (use the buttons below):
 *   <img src=x onerror="alert(1)">
 *   <svg onload="alert(document.domain)">
 *   <a href="javascript:alert(1)">click me</a>
 *
 * Note: <script> inserted via innerHTML is NOT executed by the browser
 * (HTML5 spec). Use onerror/onload/javascript: instead.
 */
"use client";

import { useEffect, useState } from "react";

type Comment = {
  id: number;
  author: string;
  body: string;
  createdAt: string;
};

const payloads = [
  { p: "<b>plain bold</b>", note: "無害なHTML" },
  { p: '<img src=x onerror="alert(1)">', note: "描画時に発火" },
  { p: '<svg onload="alert(document.domain)">', note: "SVG経由でドメイン漏えい" },
  {
    p: '<a href="javascript:alert(1)">click me</a>',
    note: "javascript: リンク (クリックで発火)",
  },
];

export default function StoredXssPage() {
  const [author, setAuthor] = useState("attacker");
  const [body, setBody] = useState("");
  const [comments, setComments] = useState<Comment[]>([]);
  const [error, setError] = useState("");

  async function load() {
    const res = await fetch("/api/comments");
    const data = await res.json();
    setComments(data.comments ?? []);
  }

  useEffect(() => {
    load();
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    const res = await fetch("/api/comments", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ author, body }),
    });
    const data = await res.json();
    if (data.error) {
      setError(data.error);
      return;
    }
    setBody("");
    load();
  }

  async function remove(id: number) {
    setError("");
    const res = await fetch("/api/comments/" + id, { method: "DELETE" });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      setError(data.error ?? "delete failed");
      return;
    }
    load();
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif" }}>
      <h1>ストアドXSSデモ (コメント)</h1>
      <p>
        サーバはコメント本文をそのまま保存し、クライアントは{" "}
        <code>dangerouslySetInnerHTML</code> で描画する。ここで送信した
        HTML/JS は閲覧者全員のブラウザで実行される。
      </p>

      <form onSubmit={submit} style={{ margin: "16px 0", display: "flex", gap: 8, flexWrap: "wrap" }}>
        <input
          type="text"
          value={author}
          onChange={(e) => setAuthor(e.target.value)}
          placeholder="投稿者"
          style={{ padding: 6, width: 140, border: "1px solid #888" }}
        />
        <input
          type="text"
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder="コメント本文 (HTML 可)"
          style={{ padding: 6, width: 360, border: "1px solid #888" }}
        />
        <button type="submit" style={{ padding: "6px 12px" }}>
          投稿
        </button>
      </form>

      <h3>ペイロード例 (クリックで入力欄に反映)</h3>
      <ul style={{ listStyle: "none", padding: 0 }}>
        {payloads.map(({ p, note }) => (
          <li key={p} style={{ margin: "4px 0" }}>
            <button
              type="button"
              onClick={() => setBody(p)}
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
        <pre style={{ background: "#400", color: "#fbb", padding: 12 }}>{error}</pre>
      )}

      <h3>コメント ({comments.length})</h3>
      <ul style={{ listStyle: "none", padding: 0 }}>
        {comments.map((c) => (
          <li
            key={c.id}
            style={{
              border: "1px solid #444",
              padding: 12,
              marginBottom: 8,
              borderRadius: 4,
            }}
          >
            <div
              style={{
                fontSize: 12,
                color: "#888",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span>
                #{c.id} 投稿者: <b>{c.author}</b> 投稿日時: {c.createdAt}
              </span>
              <button
                type="button"
                onClick={() => remove(c.id)}
                style={{
                  padding: "2px 8px",
                  border: "1px solid #888",
                  background: "transparent",
                  color: "inherit",
                  cursor: "pointer",
                  fontSize: 12,
                }}
              >
                削除
              </button>
            </div>
            {/* VULNERABLE: raw HTML from server is rendered as-is */}
            <div dangerouslySetInnerHTML={{ __html: c.body }} />
          </li>
        ))}
      </ul>
    </div>
  );
}
