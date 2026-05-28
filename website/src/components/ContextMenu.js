"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { BookOpen, Layers, Search, Copy, Check } from "lucide-react";

export default function ContextMenu() {
  const [visible, setVisible] = useState(false);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [copied, setCopied] = useState(false);
  const menuRef = useRef(null);
  const router = useRouter();

  useEffect(() => {
    const handleContextMenu = (e) => {
      e.preventDefault();
      
      // Calculate positions, keeping it inside screen limits
      const x = Math.min(e.clientX, window.innerWidth - 220);
      const y = Math.min(e.clientY, window.innerHeight - 260);
      
      setPosition({ x, y });
      setVisible(true);
    };

    const handleClickOutside = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setVisible(false);
      }
    };

    const handleKeyDown = (e) => {
      if (e.key === "F12" || e.keyCode === 123) {
        e.preventDefault();
      }
    };

    window.addEventListener("contextmenu", handleContextMenu);
    window.addEventListener("click", handleClickOutside);
    window.addEventListener("keydown", handleKeyDown);

    return () => {
      window.removeEventListener("contextmenu", handleContextMenu);
      window.removeEventListener("click", handleClickOutside);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

  const handleCopyLink = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      setCopied(true);
      setTimeout(() => {
        setCopied(false);
        setVisible(false);
      }, 1200);
    } catch (err) {
      console.error(err);
    }
  };

  const triggerSearch = () => {
    setVisible(false);
    window.dispatchEvent(new Event("open-search-modal"));
  };

  if (!visible) return null;

  return (
    <div
      ref={menuRef}
      style={{ top: position.y, left: position.x }}
      className="fixed z-50 w-52 rounded-lg border border-zinc-800 bg-zinc-900/90 backdrop-blur-md p-1.5 shadow-2xl select-none"
    >
      <div className="px-2.5 py-1.5 text-[10px] font-bold tracking-widest text-zinc-500 uppercase border-b border-zinc-800/60 mb-1">
        VScanX Actions
      </div>

      <button
        onClick={triggerSearch}
        className="w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs font-semibold text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 transition-colors cursor-pointer"
      >
        <div className="flex items-center gap-2">
          <Search size={13} className="text-zinc-500" />
          <span>Search documentation</span>
        </div>
        <kbd className="text-[9px] text-zinc-500 font-mono">⌘K</kbd>
      </button>

      <button
        onClick={() => { router.push("/docs"); setVisible(false); }}
        className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded text-xs font-semibold text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 transition-colors cursor-pointer"
      >
        <BookOpen size={13} className="text-zinc-500" />
        <span>Documentation Hub</span>
      </button>

      <button
        onClick={() => { router.push("/docs/architecture"); setVisible(false); }}
        className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded text-xs font-semibold text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 transition-colors cursor-pointer"
      >
        <Layers size={13} className="text-zinc-500" />
        <span>System Architecture</span>
      </button>

      <a
        href="https://github.com/hnikhil-dev/VScanX"
        target="_blank"
        rel="noopener noreferrer"
        onClick={() => setVisible(false)}
        className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded text-xs font-semibold text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 transition-colors cursor-pointer"
      >
        <svg className="h-3.5 w-3.5 text-zinc-500" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
        </svg>
        <span>GitHub Repository</span>
      </a>

      <div className="h-px bg-zinc-800/60 my-1" />

      <button
        onClick={handleCopyLink}
        className="w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs font-semibold text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 transition-colors cursor-pointer"
      >
        <div className="flex items-center gap-2">
          {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} className="text-zinc-500" />}
          <span>Copy Page URL</span>
        </div>
        {copied && <span className="text-[9px] text-emerald-400 font-mono">Copied!</span>}
      </button>
    </div>
  );
}
