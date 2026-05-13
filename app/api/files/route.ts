/**
 * Vulnerability: Path Traversal
 * Source: GET /api/files?name=
 * Sink: fs.readFileSync(path.join(baseDir, name))
 * CWE-22, OWASP A01:2021 — Broken Access Control
 * SAST Rules: Semgrep path-traversal-fs, CodeQL js/path-injection
 *
 * `path.join` happily resolves `..` segments. With no normalization /
 * containment check, the attacker can read any file the Node.js process
 * can access — sibling secrets, source code, /etc/passwd, etc.
 */
import { readFileSync, statSync } from "fs";
import { join } from "path";
import { NextRequest, NextResponse } from "next/server";

const baseDir = join(process.cwd(), "demo-files");

export async function GET(req: NextRequest) {
  const name = req.nextUrl.searchParams.get("name") ?? "";
  if (!name) {
    return NextResponse.json({ error: "name required" }, { status: 400 });
  }
  // VULNERABLE: no check that the resolved path stays under baseDir.
  // A safe version would resolve the path and verify it starts with baseDir,
  // or use a whitelist of allowed filenames.
  const resolved = join(baseDir, name);
  try {
    const stat = statSync(resolved);
    if (stat.isDirectory()) {
      return NextResponse.json(
        { error: "is a directory", resolved },
        { status: 400 },
      );
    }
    const content = readFileSync(resolved, "utf8");
    return NextResponse.json({ resolved, content });
  } catch (err) {
    return NextResponse.json(
      { resolved, error: (err as Error).message },
      { status: 500 },
    );
  }
}
