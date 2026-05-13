/**
 * Vulnerability: Stored XSS (server persisted, client innerHTML)
 * Source: POST /api/comments → server stores raw HTML/JS
 * Sink: dangerouslySetInnerHTML on every viewer's page
 * CWE-79, OWASP A03:2021
 * SAST Rules: Semgrep react-dangerously-set-inner-html, ESLint react/no-danger
 *
 * Payloads (use the buttons below):
 *   <img src=x onerror=alert(1)>
 *   <script>alert('stored')</script>
 *   <svg onload=alert(document.domain)>
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
  { p: "<b>plain bold</b>", note: "benign HTML" },
  { p: "<img src=x onerror=alert('stored XSS')>", note: "fires on render" },
  { p: "<svg onload=alert(document.domain)>", note: "domain leak" },
  { p: "<script>alert(1)</script>", note: "raw script tag" },
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

  return (
    <div style={{ padding: 24, fontFamily: "system-ui, sans-serif" }}>
      <h1>Stored XSS Demo (Comments)</h1>
      <p>
        Server stores the comment body verbatim; the client renders each one
        with <code>dangerouslySetInnerHTML</code>. Any HTML/JS submitted here
        runs in every viewer&apos;s browser.
      </p>

      <form onSubmit={submit} style={{ margin: "16px 0", display: "flex", gap: 8, flexWrap: "wrap" }}>
        <input
          type="text"
          value={author}
          onChange={(e) => setAuthor(e.target.value)}
          placeholder="author"
          style={{ padding: 6, width: 140, border: "1px solid #888" }}
        />
        <input
          type="text"
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder="comment body (HTML allowed)"
          style={{ padding: 6, width: 360, border: "1px solid #888" }}
        />
        <button type="submit" style={{ padding: "6px 12px" }}>
          Post
        </button>
      </form>

      <h3>Payloads to try (click to fill)</h3>
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

      <h3>Comments ({comments.length})</h3>
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
            <div style={{ fontSize: 12, color: "#888" }}>
              #{c.id} by <b>{c.author}</b> at {c.createdAt}
            </div>
            {/* VULNERABLE: raw HTML from server is rendered as-is */}
            <div dangerouslySetInnerHTML={{ __html: c.body }} />
          </li>
        ))}
      </ul>
    </div>
  );
}
