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
