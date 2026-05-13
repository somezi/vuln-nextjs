import { BackLink } from "./BackLink";

export default function VulnLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <BackLink />
      {children}
    </>
  );
}
