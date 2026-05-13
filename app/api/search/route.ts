/**
 * Vulnerability: SQL Injection (string concatenation)
 * Source: request query parameter `q`
 * Sink: raw SQL query string built via concatenation
 * CWE-89, OWASP A03:2021 - Injection
 * SAST Rules: Semgrep javascript.lang.security.audit.sqli.tainted-sql-string,
 *             SonarQube S2077, CodeQL js/sql-injection
 *
 * Payloads (try in /vuln/sql-injection):
 *   alice                       → 1 row
 *   ' OR '1'='1                 → all rows (auth bypass style)
 *   ' UNION SELECT password --  → leak password column
 *   ' OR username LIKE '%admin% → admin row
 */
import { NextRequest, NextResponse } from "next/server";
import { runQuery } from "../../lib/fakedb";

export async function GET(req: NextRequest) {
  const q = req.nextUrl.searchParams.get("q") ?? "";

  // VULNERABLE: user input concatenated directly into SQL string.
  // A safe version would use parameterized queries: db.prepare("SELECT ... WHERE username = ?").all(q)
  const sql =
    "SELECT id, username, email FROM users WHERE username = '" + q + "'";

  try {
    const rows = runQuery(sql);
    return NextResponse.json({ sql, rows });
  } catch (err) {
    return NextResponse.json(
      { sql, error: (err as Error).message },
      { status: 500 },
    );
  }
}
