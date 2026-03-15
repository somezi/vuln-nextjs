/**
 * Vulnerability: DOM-based XSS via document.write()
 * Source: URLSearchParams('content')
 * Sink: document.write()
 * SAST Rules: Semgrep dom-based-xss.document-write-url-params, SonarQube tainted document.write
 * BApp Store: AutoVader (DOM XSS) https://portswigger.net/bappstore/46a8e69964674ff8ae49774e2b720f0c
 * Payload: ?content=<script>alert(1)</script>
 */
export default function DocumentWritePage() {
  return (
    <div>
      <h1>document.write() DOM XSS Demo</h1>
      <script
        dangerouslySetInnerHTML={{
          __html: `
        // VULNERABLE: URLSearchParams flows directly to document.write()
        var params = new URLSearchParams(location.search);
        var content = params.get('content');
        if (content) {
          document.write(content);
        }
      `,
        }}
      />
    </div>
  );
}
