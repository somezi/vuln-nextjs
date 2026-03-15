/**
 * Vulnerability: Code Injection via new Function()
 * Source: URLSearchParams('body')
 * Sink: new Function(body)() - string argument is compiled and executed as code
 * SAST Rules: Semgrep detect-new-function, ESLint no-new-func
 * BApp Store: AutoVader (DOM XSS) https://portswigger.net/bappstore/46a8e69964674ff8ae49774e2b720f0c
 * Payload: ?body=alert(1)
 */
export default function FunctionConstructorPage() {
  return (
    <div>
      <h1>new Function() Code Injection Demo</h1>
      <div id="output"></div>
      <script
        dangerouslySetInnerHTML={{
          __html: `
        // VULNERABLE: URLSearchParams flows directly to new Function()
        var params = new URLSearchParams(location.search);
        var body = params.get('body');
        if (body) {
          var fn = new Function(body);
          fn();
        }
      `,
        }}
      />
    </div>
  );
}
