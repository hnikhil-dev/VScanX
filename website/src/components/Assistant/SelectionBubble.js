"use client";

import { useState, useEffect, useRef } from "react";
import { Cpu, GitFork, Database, Terminal } from "lucide-react";

export default function SelectionBubble({ onTriggerAssistant }) {
  const [bubbleState, setBubbleState] = useState({
    visible: false,
    top: 0,
    left: 0,
    selectedText: ""
  });
  
  const bubbleRef = useRef(null);

  useEffect(() => {
    const handleSelectionChange = () => {
      const selection = window.getSelection();
      if (!selection || selection.isCollapsed) {
        return;
      }

      const selectedText = selection.toString().trim();
      if (selectedText.length < 3 || selectedText.length > 500) {
        return;
      }

      const range = selection.getRangeAt(0);
      const rects = range.getClientRects();
      if (rects.length === 0) return;

      const primaryRect = rects[0];
      
      // Calculate scroll coordinates
      const scrollY = window.pageYOffset || document.documentElement.scrollTop;
      const scrollX = window.pageXOffset || document.documentElement.scrollLeft;

      // Position bubble in the center above the selection
      const top = primaryRect.top + scrollY - 42; 
      const left = primaryRect.left + scrollX + (primaryRect.width / 2);

      setBubbleState({
        visible: true,
        top,
        left,
        selectedText
      });
    };

    const handleMouseUp = (e) => {
      // If clicked inside the bubble, do not dismiss it immediately
      if (bubbleRef.current && bubbleRef.current.contains(e.target)) {
        return;
      }
      
      // Wait slightly to check selection state
      setTimeout(() => {
        const selection = window.getSelection();
        if (!selection || selection.isCollapsed) {
          setBubbleState(prev => ({ ...prev, visible: false }));
        }
      }, 50);
    };

    document.addEventListener("selectionchange", handleSelectionChange);
    document.addEventListener("mouseup", handleMouseUp);

    return () => {
      document.removeEventListener("selectionchange", handleSelectionChange);
      document.removeEventListener("mouseup", handleMouseUp);
    };
  }, []);

  if (!bubbleState.visible) return null;

  return (
    <div
      ref={bubbleRef}
      style={{
        position: "absolute",
        top: `${bubbleState.top}px`,
        left: `${bubbleState.left}px`,
        transform: "translateX(-50%)",
        zIndex: 1000
      }}
      className="flex items-center gap-0.5 bg-zinc-900/95 border border-zinc-800 text-zinc-100 rounded-md p-1 shadow-2xl backdrop-blur-md animate-fadeIn transition-all duration-150 select-none"
    >
      {/* 1. Explain Button */}
      <button
        onClick={() => {
          onTriggerAssistant(bubbleState.selectedText, "explain");
          setBubbleState(prev => ({ ...prev, visible: false }));
        }}
        title="Explain Concept"
        className="flex items-center gap-1.5 px-2 py-1 rounded hover:bg-zinc-800 text-[10px] font-mono font-bold text-zinc-300 hover:text-zinc-50 transition-colors duration-150 cursor-pointer"
      >
        <Cpu size={10} className="text-zinc-400" />
        <span>Explain</span>
      </button>
      
      <span className="w-px h-3 bg-zinc-800" />
      
      {/* 2. Trace Workflow Button */}
      <button
        onClick={() => {
          onTriggerAssistant(bubbleState.selectedText, "workflow");
          setBubbleState(prev => ({ ...prev, visible: false }));
        }}
        title="Trace Framework Stages"
        className="flex items-center gap-1.5 px-2 py-1 rounded hover:bg-zinc-800 text-[10px] font-mono font-bold text-zinc-300 hover:text-zinc-50 transition-colors duration-150 cursor-pointer"
      >
        <GitFork size={10} className="text-zinc-400" />
        <span>Trace Workflow</span>
      </button>

      <span className="w-px h-3 bg-zinc-800" />
      
      {/* 3. Explain Schema Button */}
      <button
        onClick={() => {
          onTriggerAssistant(bubbleState.selectedText, "schema");
          setBubbleState(prev => ({ ...prev, visible: false }));
        }}
        title="Explain Schema Contract"
        className="flex items-center gap-1.5 px-2 py-1 rounded hover:bg-zinc-800 text-[10px] font-mono font-bold text-zinc-300 hover:text-zinc-50 transition-colors duration-150 cursor-pointer"
      >
        <Database size={10} className="text-zinc-400" />
        <span>Schema</span>
      </button>

      <span className="w-px h-3 bg-zinc-800" />
      
      {/* 4. Find CLI Commands Button */}
      <button
        onClick={() => {
          onTriggerAssistant(bubbleState.selectedText, "commands");
          setBubbleState(prev => ({ ...prev, visible: false }));
        }}
        title="Find CLI Commands"
        className="flex items-center gap-1.5 px-2 py-1 rounded hover:bg-zinc-800 text-[10px] font-mono font-bold text-zinc-300 hover:text-zinc-50 transition-colors duration-150 cursor-pointer"
      >
        <Terminal size={10} className="text-zinc-400" />
        <span>Commands</span>
      </button>
    </div>
  );
}
