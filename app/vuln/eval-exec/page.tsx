export default function EvalExecPage() {
  return (
    <div>
      <h1>Eval Exec Demo</h1>
      <script
        dangerouslySetInnerHTML={{
          __html: `
        // VULNERABLE: URLSearchParams flows to eval()
        var params = new URLSearchParams(location.search);
        var code = params.get('code');
        if (code) { eval(code); }
      `,
        }}
      />
    </div>
  );
}
