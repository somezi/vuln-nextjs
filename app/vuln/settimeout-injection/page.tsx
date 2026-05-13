/**
 * Vulnerability: Code Injection via setTimeout(string)
 * Source: URLSearchParams('action')
 * Sink: setTimeout(string, 0) - string argument is evaluated as code
 * SAST Rules: ESLint no-implied-eval, SonarQube S1523
 * BApp Store: AutoVader (DOM XSS) https://portswigger.net/bappstore/46a8e69964674ff8ae49774e2b720f0c
 * Payload: ?action=alert(1)
 */
export default function SetTimeoutInjectionPage() {
  return (
    <div>
      <h1>setTimeout 文字列インジェクションデモ</h1>
      <div id="output"></div>
      <script
        dangerouslySetInnerHTML={{
          __html: `
        // VULNERABLE: URLSearchParams flows directly to setTimeout(string)
        var params = new URLSearchParams(location.search);
        var action = params.get('action');
        if (action) {
          setTimeout(action, 0);
        }
      `,
        }}
      />
    </div>
  );
}
