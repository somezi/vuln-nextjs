/**
 * Vulnerability: Prototype Pollution
 * Source: URLSearchParams('key', 'value')
 * Sink: obj.__proto__[key] = value
 * SAST Rules: Semgrep prototype-pollution, SonarQube S5147 (WS-JS-021)
 * BApp Store: AutoVader (Prototype Pollution) https://portswigger.net/bappstore/46a8e69964674ff8ae49774e2b720f0c
 *            Server-Side Prototype Pollution Scanner https://portswigger.net/bappstore/c1d4bd60626d4178a54d36ee802cf7e8
 *            Prototype Pollution Gadgets Finder https://portswigger.net/bappstore/fcbc58b33fc1486d9a795dedba2ccbbb
 * Payload: ?key=polluted&value=true
 */
export default function ProtoPollutionPage() {
  return (
    <div>
      <h1>Prototype Pollution Demo</h1>
      <script
        dangerouslySetInnerHTML={{
          __html: `
        // VULNERABLE: prototype pollution via URL params
        var params = new URLSearchParams(location.search);
        var key = params.get('key');
        var value = params.get('value');
        if (key && value) {
          var obj = {};
          obj.__proto__[key] = value;
        }
      `,
        }}
      />
    </div>
  );
}
