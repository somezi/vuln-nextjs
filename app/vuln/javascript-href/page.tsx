/**
 * Vulnerability: XSS via javascript: URI scheme
 * Source: URLSearchParams('href')
 * Sink: a.href = href - javascript: scheme executes code on click
 * SAST Rules: Semgrep javascript-scheme-xss, React jsx-no-script-url
 * BApp Store: AutoVader (DOM XSS) https://portswigger.net/bappstore/46a8e69964674ff8ae49774e2b720f0c
 * Payload: ?href=javascript:alert(1)
 */
export default function JavascriptHrefPage() {
  return (
    <div>
      <h1>javascript: Scheme XSS Demo</h1>
      <div id="output"></div>
      <script
        dangerouslySetInnerHTML={{
          __html: `
        // VULNERABLE: URLSearchParams flows directly to a.href (javascript: scheme)
        var params = new URLSearchParams(location.search);
        var href = params.get('href');
        if (href) {
          var a = document.createElement('a');
          a.href = href;
          a.textContent = 'Click me';
          document.getElementById('output').appendChild(a);
        }
      `,
        }}
      />
    </div>
  );
}
