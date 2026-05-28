"use client";

import { useState } from "react";
import { Copy, Check } from "lucide-react";

export default function CodeBlock({ code, language = "bash" }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2050);
    } catch (err) {
      console.error("Failed to copy: ", err);
    }
  };

  return (
    <div className="relative group rounded-md border border-zinc-900 bg-zinc-950 p-4 font-mono text-sm text-zinc-350 select-all overflow-x-auto w-full mb-4">
      <button
        onClick={handleCopy}
        className="absolute right-4 top-3.5 p-2 rounded border border-zinc-900 bg-zinc-900/50 hover:bg-zinc-800 hover:text-zinc-100 text-zinc-500 opacity-0 group-hover:opacity-100 transition-all duration-150 cursor-pointer"
        title="Copy Command"
      >
        {copied ? <Check size={14} className="text-emerald-400 font-bold" /> : <Copy size={14} />}
      </button>
      <pre className="m-0 leading-relaxed text-zinc-300 font-mono pr-12 select-text font-semibold">{code}</pre>
    </div>
  );
}
