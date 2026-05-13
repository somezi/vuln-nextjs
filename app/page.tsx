import Image from "next/image";

export default function Home() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-50 font-sans dark:bg-black">
      <main className="flex min-h-screen w-full max-w-3xl flex-col gap-10 py-20 px-8 bg-white dark:bg-black sm:px-16">
        <Image
          className="dark:invert"
          src="/next.svg"
          alt="Next.js logo"
          width={100}
          height={20}
          priority
        />

        <div className="flex flex-col gap-4">
          <h1 className="text-3xl font-semibold tracking-tight text-black dark:text-zinc-50">
            Vulnerable Next.js Demos
          </h1>
          <p className="max-w-xl text-base leading-7 text-zinc-600 dark:text-zinc-400">
            Deliberately vulnerable pages for scanner testing. Pick a demo
            below, or see the full index.
          </p>
          <a
            href="/vuln"
            className="inline-flex h-12 w-fit items-center justify-center rounded-full bg-foreground px-6 text-background font-medium transition-colors hover:bg-[#383838] dark:hover:bg-[#ccc]"
          >
            View all vulnerable demos →
          </a>
        </div>

        <div className="flex flex-col gap-4 text-sm text-zinc-600 dark:text-zinc-400 sm:flex-row sm:gap-6">
          <a
            href="https://vercel.com/new?utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:underline"
          >
            Deploy on Vercel
          </a>
          <a
            href="https://nextjs.org/docs?utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:underline"
          >
            Next.js Documentation
          </a>
        </div>
      </main>
    </div>
  );
}
