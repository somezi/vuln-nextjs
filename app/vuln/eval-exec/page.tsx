/**
 * Vulnerability: Arbitrary Code Execution via eval()
 * Source: URLSearchParams('code')
 * Sink: eval()
 * SAST Rules: Semgrep detect-eval, ESLint no-eval, SonarQube S1523 (WS-JS-006)
 * BApp Store: AutoVader (DOM XSS) https://portswigger.net/bappstore/46a8e69964674ff8ae49774e2b720f0c
 * Payload: ?code=alert(1)
 */
export default function EvalExecPage() {
  return (
    <div>
      <h1>Eval Exec Demo</h1>
      <script
        dangerouslySetInnerHTML={{
          __html: `
        // VULNERABLE: URLSearchParams flows to eval()
        var params = new URLSearchParams(location.search);
        var code = params.get('code');
        if (code) { eval(code); }
      `,
        }}
      />
    </div>
  );
}
