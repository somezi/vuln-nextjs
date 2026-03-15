export default function VulnIndexPage() {
  return (
    <div>
      <h1>Vulnerable Demo Pages</h1>
      <ul>
        <li>
          <a href="/vuln/xss-hash">XSS via location.hash (WS-JS-019)</a>
        </li>
        <li>
          <a href="/vuln/eval-exec">eval() execution sink (WS-JS-006)</a>
        </li>
        <li>
          <a href="/vuln/proto-pollution">Prototype pollution (WS-JS-021)</a>
        </li>
        <li>
          <a href="/vuln/dynamic-property">Dynamic property access XSS</a>
        </li>
        <li>
          <a href="/vuln/postmessage">PostMessage without origin check</a>
        </li>
        <li>
          <a href="/vuln/document-write">document.write() DOM XSS</a>
        </li>
        <li>
          <a href="/vuln/settimeout-injection">setTimeout string injection</a>
        </li>
        <li>
          <a href="/vuln/open-redirect">Open redirect via location.href</a>
        </li>
        <li>
          <a href="/vuln/function-constructor">new Function() code injection</a>
        </li>
        <li>
          <a href="/vuln/script-injection">Dynamic script.src injection</a>
        </li>
        <li>
          <a href="/vuln/javascript-href">javascript: scheme XSS</a>
        </li>
      </ul>
    </div>
  );
}
