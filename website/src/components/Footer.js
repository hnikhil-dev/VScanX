import Link from "next/link";

export default function Footer() {
  return (
    <footer className="mt-auto border-t border-zinc-900 bg-zinc-950 py-10 text-zinc-500">
      <div className="w-full px-6 md:px-12 lg:px-16 flex flex-col sm:flex-row items-center justify-between gap-6 text-sm">
        <div>
          <span>&copy; {new Date().getFullYear()} VScanX. High-performance security analysis. Licensed under MIT.</span>
        </div>
        <div className="flex gap-8">
          <Link href="/docs" className="hover:text-zinc-300 transition-colors font-medium">Documentation</Link>
          <Link href="/docs/architecture" className="hover:text-zinc-300 transition-colors font-medium">Architecture</Link>
          <a href="https://github.com/hnikhil-dev/VScanX" target="_blank" rel="noopener noreferrer" className="hover:text-zinc-300 transition-colors font-medium">GitHub</a>
        </div>
      </div>
    </footer>
  );
}
