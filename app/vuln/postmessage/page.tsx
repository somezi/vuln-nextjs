export default function PostMessagePage() {
  return (
    <div>
      <h1>PostMessage Demo</h1>
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
