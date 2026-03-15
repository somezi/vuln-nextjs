/**
 * Vulnerability: DOM-based XSS (Reflected)
 * Source: location.hash
 * Sink: innerHTML
 * SAST Rules: Semgrep dom-based-xss, SonarQube S5131 (WS-JS-019)
 * BApp Store: AutoVader (DOM XSS) https://portswigger.net/bappstore/46a8e69964674ff8ae49774e2b720f0c
 * Payload: #<img src=x onerror=alert(1)>
 */
export default function XssHashPage() {
  return (
    <div>
      <h1>Hash XSS Demo</h1>
      <div id="output"></div>
      <script
        dangerouslySetInnerHTML={{
          __html: `
        // VULNERABLE: location.hash flows directly to innerHTML
        var hash = location.hash.substring(1);
        document.getElementById('output').innerHTML = hash;
      `,
        }}
      />
    </div>
  );
}
