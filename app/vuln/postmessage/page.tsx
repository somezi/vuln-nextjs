/**
 * Vulnerability: DOM-based XSS via postMessage (Missing Origin Validation)
 * Source: window message event (event.data)
 * Sink: innerHTML
 * SAST Rules: Semgrep postmessage-origin-check, SonarQube S2819
 * BApp Store: AutoVader (PostMessage) https://portswigger.net/bappstore/46a8e69964674ff8ae49774e2b720f0c
 * Payload: postMessage('<img src=x onerror=alert(1)>', '*') from attacker page
 */
export default function PostMessagePage() {
  return (
    <div>
      <h1>postMessage デモ</h1>
      <div id="display"></div>
      <script
        dangerouslySetInnerHTML={{
          __html: `
        // VULNERABLE: no origin check on postMessage handler
        window.addEventListener('message', function(event) {
          document.getElementById('display').innerHTML = event.data;
        });
      `,
        }}
      />
    </div>
  );
}
