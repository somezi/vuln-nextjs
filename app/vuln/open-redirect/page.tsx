/**
 * Vulnerability: Open Redirect
 * Source: URLSearchParams('url')
 * Sink: location.href = url
 * SAST Rules: Semgrep open-redirect-from-url, SonarQube S5146
 * BApp Store: AutoVader (Client-side Redirects) https://portswigger.net/bappstore/46a8e69964674ff8ae49774e2b720f0c
 * Payload: ?url=https://evil.example.com
 */
export default function OpenRedirectPage() {
  return (
    <div>
      <h1>Open Redirect Demo</h1>
      <script
        dangerouslySetInnerHTML={{
          __html: `
        // VULNERABLE: URLSearchParams flows directly to location.href
        var params = new URLSearchParams(location.search);
        var url = params.get('url');
        if (url) {
          location.href = url;
        }
      `,
        }}
      />
    </div>
  );
}
