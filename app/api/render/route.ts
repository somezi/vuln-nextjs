/**
 * Vulnerability: Server-Side Template Injection (SSTI)
 * Source: POST /api/render body.template
 * Sink: renderTemplate() → new Function() inside a server route
 * CWE-94 (Code Injection) / CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine)
 * OWASP A03:2021 — Injection
 * SAST Rules: Semgrep tainted-new-function, CodeQL js/code-injection
 *
 * The renderer evaluates `<%= expr %>` as JavaScript on the Node.js server,
 * giving an attacker full process-level access (env vars, filesystem,
 * outbound network) within the serverless function.
 */
import { NextRequest, NextResponse } from "next/server";
import { renderTemplate } from "../../lib/render";

export async function POST(req: NextRequest) {
  const { template } = (await req.json()) as { template?: string };
  if (typeof template !== "string") {
    return NextResponse.json({ error: "template required" }, { status: 400 });
  }
  try {
    const output = renderTemplate(template);
    return NextResponse.json({ output });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message },
      { status: 500 },
    );
  }
}
