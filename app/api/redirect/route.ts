/**
 * Vulnerability: Server-side Open Redirect
 * Source: GET /api/redirect?to=
 * Sink: NextResponse.redirect(new URL(to, req.url))
 * CWE-601 · OWASP A01:2021 — Broken Access Control
 * SAST Rules: Semgrep open-redirect, CodeQL js/server-side-unvalidated-url-redirection
 *
 * Common abuse:
 *   - Phishing: vuln site → attacker domain (the user sees the trusted
 *     origin in the link, gets redirected to evil)
 *   - OAuth/SSO callback hijack: the IdP returns an authorization code
 *     to the configured callback, but the relying party blindly forwards
 *     to ?to=... — attacker steals the code.
 */
import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  const to = req.nextUrl.searchParams.get("to") ?? "/";
  // VULNERABLE: no allow-list, no same-origin check.
  // Protocol-relative URLs ("//evil.example.com/...") inherit the
  // current scheme, so the redirect lands on the attacker's domain.
  return NextResponse.redirect(new URL(to, req.url));
}
