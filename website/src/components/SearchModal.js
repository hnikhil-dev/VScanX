"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Search, FileText, ArrowRight } from "lucide-react";

export default function SearchModal({ isOpen, onClose }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const router = useRouter();
  const modalRef = useRef(null);

  const docIndices = [
    { label: "Getting Started", description: "Initialize environment and execute first scan.", href: "/docs" },
    { label: "Core Concepts", description: "State tracking, discovery, and decoupled event loops.", href: "/docs/core-concepts" },
    { label: "Verification Workflow", description: "Probing phase vs active verification execution.", href: "/docs/verification-workflow" },
    { label: "Replay & Diff Engine", description: "Snapshot comparative state mutations and delta logs.", href: "/docs/replay-diff" },
    { label: "Canonical Findings", description: "Vulnerability reporting schemas and response payloads.", href: "/docs/canonical-findings" },
    { label: "Scanner Modules", description: "Web Application, Network, Smart Contract, and LLM domains.", href: "/docs/modules" },
    { label: "CLI Interface Reference", description: "Operational CLI driver arguments and flags.", href: "/docs/cli" },
    { label: "System Internals", description: "Unified multi-threaded event dispatching loop.", href: "/docs/internals" },
    { label: "System Architecture Diagram", description: "Visual flowcharts for lifecycle, replays, and bus channels.", href: "/docs/architecture" }
  ];

  useEffect(() => {
    if (!query) {
      setResults([]);
      return;
    }

    const filtered = docIndices.filter(
      (item) =>
        item.label.toLowerCase().includes(query.toLowerCase()) ||
        item.description.toLowerCase().includes(query.toLowerCase())
    );
    setResults(filtered);
    setSelectedIndex(0);
  }, [query]);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (!isOpen) return;

      if (e.key === "Escape") {
        onClose();
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIndex((prev) => (prev + 1) % Math.max(1, results.length));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIndex((prev) => (prev - 1 + results.length) % Math.max(1, results.length));
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (results[selectedIndex]) {
          router.push(results[selectedIndex].href);
          onClose();
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, results, selectedIndex]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 px-4 bg-zinc-950/80 backdrop-blur-sm">
      <div 
        ref={modalRef}
        className="w-full max-w-2xl rounded-xl border border-zinc-900 bg-zinc-900 shadow-2xl overflow-hidden flex flex-col min-h-[220px]"
      >
        {/* Input area */}
        <div className="relative flex items-center border-b border-zinc-900 p-5">
          <Search size={20} className="text-zinc-500 mr-4" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search documentation sections..."
            className="w-full bg-transparent text-base text-zinc-100 placeholder-zinc-500 focus:outline-none"
            autoFocus
          />
        </div>

        {/* Results list */}
        <div className="flex-1 max-h-80 overflow-y-auto p-3">
          {results.length > 0 ? (
            results.map((item, idx) => (
              <button
                key={idx}
                onClick={() => {
                  router.push(item.href);
                  onClose();
                }}
                className={`w-full text-left flex items-start gap-4 p-4 rounded-lg text-sm transition-all duration-150 ${
                  selectedIndex === idx ? "bg-zinc-800/80 text-zinc-100" : "text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200"
                }`}
              >
                <FileText size={18} className="text-zinc-500 mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="font-bold text-zinc-200 text-sm">{item.label}</div>
                  <div className="text-xs text-zinc-500 mt-1 truncate">{item.description}</div>
                </div>
                <ArrowRight size={16} className="text-zinc-600 self-center" />
              </button>
            ))
          ) : query ? (
            <div className="p-10 text-center text-sm text-zinc-500 font-mono">
              No results found for "{query}"
            </div>
          ) : (
            <div className="p-6 text-sm text-zinc-500 font-mono">
              Type to start searching... e.g. <span className="text-zinc-400">verification</span> or <span className="text-zinc-400">replay</span>
            </div>
          )}
        </div>

        {/* Help footer */}
        <div className="border-t border-zinc-900 bg-zinc-950 px-5 py-3 flex items-center justify-between text-xs text-zinc-500 font-mono">
          <span>Use <kbd>↑↓</kbd> to navigate, <kbd>Enter</kbd> to select</span>
          <span><kbd>Esc</kbd> to close</span>
        </div>
      </div>
      {/* Background click close handler */}
      <div className="absolute inset-0 -z-10" onClick={onClose} />
    </div>
  );
}
