"use client";

import { useState, useEffect } from "react";
import LinkNext from "next/link";
import { Search } from "lucide-react";
import SearchModal from "./SearchModal";

export default function Navbar() {
  const [isSearchOpen, setIsSearchOpen] = useState(false);

  useEffect(() => {
    const handleGlobalKeydown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setIsSearchOpen(true);
      }
    };

    const handleOpenSearchEvent = () => {
      setIsSearchOpen(true);
    };

    window.addEventListener("keydown", handleGlobalKeydown);
    window.addEventListener("open-search-modal", handleOpenSearchEvent);

    return () => {
      window.removeEventListener("keydown", handleGlobalKeydown);
      window.removeEventListener("open-search-modal", handleOpenSearchEvent);
    };
  }, []);

  return (
    <>
      <nav className="sticky top-0 z-50 w-full border-b border-zinc-900 bg-zinc-950/70 backdrop-blur-md">
        <div className="w-full px-6 md:px-12 lg:px-16">
          <div className="flex h-20 items-center justify-between">
            {/* Logo / Wordmark */}
            <div className="flex items-center gap-3">
              <LinkNext href="/" className="flex items-center gap-3 group">
                <img 
                  src="/logo.png" 
                  alt="VScanX Logo" 
                  className="h-8 w-8 object-contain rounded-md"
                />
                <span className="font-sans font-bold text-xl tracking-tight text-zinc-50 group-hover:text-white transition-colors duration-150">
                  VScanX
                </span>
              </LinkNext>
            </div>

            {/* Navigation Links */}
            <div className="hidden md:flex items-center gap-10">
              <LinkNext 
                href="/docs" 
                className="text-base font-semibold text-zinc-400 hover:text-zinc-200 transition-colors duration-150"
              >
                Documentation
              </LinkNext>
              <LinkNext 
                href="/docs/architecture" 
                className="text-base font-semibold text-zinc-400 hover:text-zinc-200 transition-colors duration-150"
              >
                Architecture
              </LinkNext>
              <LinkNext 
                href="/sandbox" 
                className="text-base font-semibold text-zinc-400 hover:text-zinc-200 transition-colors duration-150"
              >
                Sandbox
              </LinkNext>
              <a 
                href="https://github.com/hnikhil-dev/VScanX" 
                target="_blank" 
                rel="noopener noreferrer" 
                className="text-base font-semibold text-zinc-400 hover:text-zinc-200 transition-colors duration-150 flex items-center gap-2"
              >
                <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                </svg>
                GitHub
              </a>
            </div>

            {/* Interactive Search Palette & Buttons */}
            <div className="flex items-center gap-6">
              <button
                onClick={() => setIsSearchOpen(true)}
                className="relative hidden sm:flex items-center w-80 rounded-md border border-zinc-900 bg-zinc-900/40 py-2.5 pl-10 pr-16 text-sm text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900/80 transition-all duration-150 cursor-pointer"
              >
                <div className="absolute left-3.5 flex items-center pointer-events-none text-zinc-500">
                  <Search size={16} />
                </div>
                <span className="text-sm font-sans font-medium">Search documentation...</span>
                <div className="absolute right-3.5 flex items-center pointer-events-none">
                  <kbd className="rounded border border-zinc-900 bg-zinc-950 px-2 py-0.5 text-[10px] text-zinc-500 font-mono">
                    ⌘K
                  </kbd>
                </div>
              </button>

              <LinkNext 
                href="/docs" 
                className="rounded bg-zinc-50 px-5 py-2.5 text-sm font-semibold text-zinc-950 hover:bg-zinc-200 transition-all duration-150 focus-visible:outline-none cursor-pointer"
              >
                Get Started
              </LinkNext>
            </div>
          </div>
        </div>
      </nav>

      {/* Globally mounted interactive search palette */}
      <SearchModal isOpen={isSearchOpen} onClose={() => setIsSearchOpen(false)} />
    </>
  );
}
