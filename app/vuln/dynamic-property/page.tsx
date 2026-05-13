/**
 * Vulnerability: DOM-based XSS via Dynamic Property Access
 * Source: location.hash
 * Sink: self[hash]() - arbitrary global function execution
 * SAST Rules: Semgrep dynamic-property-access, SonarQube tainted bracket notation
 * BApp Store: AutoVader (DOM XSS) https://portswigger.net/bappstore/46a8e69964674ff8ae49774e2b720f0c
 * Payload: #alert
 */
export default function DynamicPropertyPage() {
  return (
    <div>
      <h1>動的プロパティアクセスデモ</h1>
      <script
        dangerouslySetInnerHTML={{
          __html: `
        // VULNERABLE: self[location.hash.substr(1)]() executes arbitrary global functions
        // Attack: visit with #alert in URL
        if (location.hash) {
          self[location.hash.substr(1)]('XSS demo');
        }
      `,
        }}
      />
    </div>
  );
}
