/**
 * Vulnerability: Stored XSS — server returns raw user input
 * Source: POST /api/comments body { author, body }
 * Sink: response JSON consumed by client as innerHTML
 * CWE-79, OWASP A03:2021
 *
 * No sanitization is applied. Any HTML/JS submitted via `body` will be
 * served back to every viewer of /vuln/stored-xss.
 */
import { NextRequest, NextResponse } from "next/server";
import { addComment, listComments } from "../../lib/comments";

export async function GET() {
  return NextResponse.json({ comments: listComments() });
}

export async function POST(req: NextRequest) {
  const { author, body } = (await req.json()) as {
    author?: string;
    body?: string;
  };
  if (!author || !body) {
    return NextResponse.json({ error: "author and body required" }, { status: 400 });
  }
  // VULNERABLE: no escaping/sanitization before persisting raw HTML
  const c = addComment(author, body);
  return NextResponse.json({ comment: c });
}
