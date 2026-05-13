/**
 * Minimal in-memory SQL engine for demo purposes only.
 * Supports a tiny subset of SQL so that classic SQL-injection payloads
 * (' OR '1'='1, UNION SELECT, -- comments) behave as they would against
 * a real RDBMS. Do not use outside of vulnerability demos.
 */

type Row = Record<string, string | number>;

const users: Row[] = [
  { id: 1, username: "alice", email: "alice@example.com", password: "alice123" },
  { id: 2, username: "bob", email: "bob@example.com", password: "hunter2" },
  { id: 3, username: "carol", email: "carol@example.com", password: "p@ssw0rd" },
  { id: 4, username: "admin", email: "admin@example.com", password: "S3cret!Adm1n" },
];

const secrets: Row[] = [
  { id: 1, name: "flag", value: "FLAG{sql_injection_demo_pwned}" },
  { id: 2, name: "api_key", value: "sk_live_DEMO_ONLY_NOT_REAL_KEY" },
];

const tables: Record<string, Row[]> = { users, secrets };

function stripComments(sql: string): string {
  const i = sql.indexOf("--");
  return (i === -1 ? sql : sql.slice(0, i)).trim().replace(/;$/, "");
}

function splitTopLevel(s: string, sep: RegExp): string[] {
  const parts: string[] = [];
  let buf = "";
  let inStr = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'") inStr = !inStr;
    if (!inStr) {
      const rest = s.slice(i);
      const m = rest.match(sep);
      if (m && m.index === 0) {
        parts.push(buf);
        buf = "";
        i += m[0].length - 1;
        continue;
      }
    }
    buf += c;
  }
  parts.push(buf);
  return parts.map((p) => p.trim()).filter(Boolean);
}

function evalCondition(row: Row, cond: string): boolean {
  cond = cond.trim();
  if (!cond) return true;

  const orParts = splitTopLevel(cond, /^\s+OR\s+/i);
  if (orParts.length > 1) return orParts.some((p) => evalCondition(row, p));

  const andParts = splitTopLevel(cond, /^\s+AND\s+/i);
  if (andParts.length > 1) return andParts.every((p) => evalCondition(row, p));

  if (cond.startsWith("(") && cond.endsWith(")")) {
    return evalCondition(row, cond.slice(1, -1));
  }

  const like = cond.match(/^(\w+)\s+LIKE\s+'([^']*)'$/i);
  if (like) {
    const [, col, pat] = like;
    const re = new RegExp(
      "^" + pat.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/%/g, ".*").replace(/_/g, ".") + "$",
      "i",
    );
    return re.test(String(row[col] ?? ""));
  }

  const eq = cond.match(/^(.+?)\s*=\s*(.+)$/);
  if (eq) {
    const lhs = resolveOperand(row, eq[1].trim());
    const rhs = resolveOperand(row, eq[2].trim());
    return String(lhs) === String(rhs);
  }

  return false;
}

function resolveOperand(row: Row, tok: string): string | number {
  if (tok.startsWith("'") && tok.endsWith("'")) return tok.slice(1, -1);
  if (/^-?\d+$/.test(tok)) return Number(tok);
  return row[tok] ?? "";
}

function executeSelect(sql: string): Row[] {
  const m = sql.match(/^SELECT\s+(.+?)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+))?$/i);
  if (!m) throw new Error("syntax error near: " + sql);
  const [, colsRaw, table, where] = m;
  const rows = tables[table.toLowerCase()];
  if (!rows) throw new Error("no such table: " + table);

  const filtered = rows.filter((r) => evalCondition(r, where ?? ""));
  const cols = colsRaw.split(",").map((c) => c.trim());

  return filtered.map((r) => {
    const out: Row = {};
    for (const c of cols) {
      if (c === "*") Object.assign(out, r);
      else out[c] = r[c] ?? "";
    }
    return out;
  });
}

export function runQuery(sql: string): Row[] {
  const cleaned = stripComments(sql);
  const parts = splitTopLevel(cleaned, /^\s+UNION(?:\s+ALL)?\s+/i);
  return parts.flatMap(executeSelect);
}
