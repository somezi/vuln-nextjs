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
