export default function DynamicPropertyPage() {
  return (
    <div>
      <h1>Dynamic Property Access Demo</h1>
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
