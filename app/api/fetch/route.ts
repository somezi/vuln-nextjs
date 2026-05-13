/**
 * Vulnerability: Server-Side Request Forgery (SSRF)
 * Source: GET /api/fetch?url=
 * Sink: fetch(url) inside a server route
 * CWE-918 · OWASP A10:2021 — Server-Side Request Forgery
 * SAST Rules: Semgrep server-side-request-forgery, CodeQL js/request-forgery
 *
 * The server makes an outbound HTTP request to whatever URL the caller
 * provides — no allow-list, no scheme check, no DNS-rebind protection.
 * Classic abuses:
 *   - Reach internal services bound to localhost / private IPs
 *   - Read cloud instance metadata (AWS 169.254.169.254 — gives IAM creds
 *     on EC2; Lambda/Vercel use IMDS-less or different endpoints)
 *   - Port-scan internal network from the server's vantage point
 */
import { NextRequest, NextResponse } from "next/server";

const MAX_BODY = 10_000;

export async function GET(req: NextRequest) {
  const url = req.nextUrl.searchParams.get("url");
  if (!url) {
    return NextResponse.json({ error: "url required" }, { status: 400 });
  }
  try {
    // VULNERABLE: no validation of scheme, host, or IP range.
    const res = await fetch(url, {
      signal: AbortSignal.timeout(5_000),
      redirect: "follow",
    });
    const text = await res.text();
    return NextResponse.json({
      requestedUrl: url,
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      body: text.slice(0, MAX_BODY),
      truncated: text.length > MAX_BODY,
    });
  } catch (err) {
    const e = err as Error & { cause?: Error & { code?: string } };
    const cause = e.cause;
    const detail = cause
      ? `${e.message}: ${cause.code ? cause.code + " " : ""}${cause.message}`
      : e.message;
    return NextResponse.json(
      { requestedUrl: url, error: detail },
      { status: 502 },
    );
  }
}
