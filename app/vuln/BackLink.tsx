"use client";

import { usePathname } from "next/navigation";

export function BackLink() {
  const pathname = usePathname();
  if (pathname === "/vuln") return null;
  return (
    <div style={{ padding: "12px 24px" }}>
      <a
        href="/vuln"
        style={{
          fontFamily: "system-ui, sans-serif",
          fontSize: 14,
          textDecoration: "none",
          color: "inherit",
          padding: "4px 8px",
          border: "1px solid #888",
          borderRadius: 4,
        }}
      >
        ← All demos
      </a>
    </div>
  );
}
