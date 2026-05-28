"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { 
  X, Cpu, GitFork, Database, Terminal, ChevronRight, Bookmark, Sliders
} from "lucide-react";
import { retrieveDocumentation } from "./searchEngine";
import { synthesizeContext } from "./synthesisEngine";

// Hardened line-by-line markdown renderer for structured technical output
function renderMarkdown(text) {
  if (!text) return null;
  
  const lines = text.split("\n");
  const elements = [];
  
  let inCodeBlock = false;
  let codeBlockLines = [];
  let codeBlockLang = "";
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const key = `ln-${i}`;
    
    // Skip Grounding/Retrieval indicator headers completely from visual rendering
    if (line.startsWith("### Grounding Evaluation") || line.startsWith("### confidence Index") || line.startsWith("### Retrieval-Constrained")) {
      continue;
    }
    if (line.startsWith("*(") && line.endsWith(")*")) {
      continue;
    }
    
    // Handle fenced code blocks dynamically
    if (line.startsWith("```")) {
      if (inCodeBlock) {
        // End of code block, compile and render as clean terminal panel
        const codeContent = codeBlockLines.join("\n");
        elements.push(
          <pre key={`code-${i}`} className="bg-zinc-950 text-zinc-400 font-mono text-[12px] p-4.5 rounded-lg border border-zinc-900/60 overflow-x-auto my-4.5 select-text leading-relaxed tracking-tight">
            <code>{codeContent}</code>
          </pre>
        );
        inCodeBlock = false;
        codeBlockLines = [];
        codeBlockLang = "";
      } else {
        // Start of code block
        inCodeBlock = true;
        codeBlockLang = line.replace("```", "").trim();
      }
      continue;
    }
    
    if (inCodeBlock) {
      codeBlockLines.push(line);
      continue;
    }
    
    // Section headings (### Section Title)
    if (line.startsWith("### ")) {
      elements.push(
        <h4 key={key} className="font-mono font-bold text-zinc-100 mt-6 mb-3.5 border-b border-zinc-900 pb-2 text-[13px] sm:text-[14px] tracking-wide uppercase">
          {line.replace("### ", "")}
        </h4>
      );
      continue;
    }
    
    // Sub-headings (#### Section Sub-title)
    if (line.startsWith("#### ")) {
      elements.push(
        <h5 key={key} className="font-mono font-semibold text-zinc-205 mt-4.5 mb-2 text-[12px] sm:text-[13px] tracking-wide uppercase">
          {line.replace("#### ", "")}
        </h5>
      );
      continue;
    }
    
    // Numbered list items (e.g. "1. **Step:** desc")
    const numMatch = line.match(/^(\d+)\.\s(.*)/);
    if (numMatch) {
      const num = numMatch[1];
      const content = numMatch[2];
      elements.push(
        <div key={key} className="flex gap-2.5 items-start pl-1 py-1.5">
          <span className="text-indigo-400 font-mono text-[12px] select-none mt-0.5 font-bold">{num}.</span>
          <span className="text-zinc-400 font-sans text-[15px] leading-7" 
                dangerouslySetInnerHTML={{ __html: formatInline(content) }} />
        </div>
      );
      continue;
    }
    
    // Bullet list items (e.g. "- **Key:** value")
    if (line.startsWith("- ")) {
      const content = line.substring(2);
      elements.push(
        <div key={key} className="flex gap-2.5 items-start pl-1 py-1">
          <span className="text-indigo-500 font-mono mt-2 select-none text-[8px]">•</span>
          <span className="text-zinc-400 font-sans text-[15px] leading-7" 
                dangerouslySetInnerHTML={{ __html: formatInline(content) }} />
        </div>
      );
      continue;
    }
    
    // Empty lines become whitespace spacing
    if (line.trim() === "") {
      elements.push(<div key={key} className="h-2" />);
      continue;
    }
    
    // ASCII diagrams or telemetry timeline headers
    if (line.includes("────➔") || line.includes("──➔") || (line.startsWith("[") && line.endsWith("]"))) {
      elements.push(
        <pre key={key} className="bg-zinc-950 text-zinc-500 font-mono text-[11px] p-3.5 rounded border border-zinc-900/60 overflow-x-auto my-3 select-text leading-normal tracking-tight">
          {line}
        </pre>
      );
      continue;
    }
    
    // Standard paragraph text
    elements.push(
      <p key={key} className="text-zinc-400 py-1 text-[15px] font-sans leading-7" 
         dangerouslySetInnerHTML={{ __html: formatInline(line) }} />
    );
  }
  
  return elements;
}

// Escapes raw entities to seal XSS vectors, and parses inline markdown tags
function formatInline(text) {
  if (!text) return "";
  
  // Escape raw HTML characters to enforce strict XSS security
  const escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
    
  return escaped
    .replace(/\*\*(.*?)\*\*/g, '<strong class="text-zinc-200 font-semibold">$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code class="bg-zinc-900 text-zinc-250 font-mono px-1.5 py-0.5 rounded text-[12px] font-medium">$1</code>')
    .replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2" class="text-indigo-400 hover:underline font-medium">$1</a>');
}

function parseRefinementIntent(text) {
  const query = (text || "").toLowerCase();
  
  if (query.includes("replay lifecycle") || query.includes("replay stages") || query.includes("stages only")) {
    return { intent: "Replay Lifecycle", tab: "workflow" };
  }
  if (query.includes("state diff") || query.includes("diff evolution") || query.includes("diff")) {
    return { intent: "State Diff", tab: "explain" };
  }
  if (query.includes("snapshot mapping") || query.includes("snapshot")) {
    return { intent: "Snapshot Mapping", tab: "explain" };
  }
  
  if (query.includes("field definitions") || query.includes("expand schema fields") || query.includes("fields")) {
    return { intent: "Field Definitions", tab: "schema" };
  }
  if (query.includes("contract structure") || query.includes("inspect event contracts") || query.includes("contract")) {
    return { intent: "Contract Structure", tab: "schema" };
  }
  if (query.includes("payload mapping") || query.includes("payload")) {
    return { intent: "Payload Mapping", tab: "schema" };
  }
  
  if (query.includes("related flags") || query.includes("flags")) {
    return { intent: "Related Flags", tab: "commands" };
  }
  if (query.includes("verification modes") || query.includes("verification boundary") || query.includes("explain verification boundary")) {
    return { intent: "Verification Modes", tab: "commands" };
  }
  if (query.includes("replay commands") || query.includes("show related commands") || query.includes("commands")) {
    return { intent: "Replay Commands", tab: "commands" };
  }
  
  if (query.includes("registration flow") || query.includes("lifecycle") || query.includes("trace plugin lifecycle")) {
    return { intent: "Registration Flow", tab: "workflow" };
  }
  if (query.includes("event subscription") || query.includes("subscription")) {
    return { intent: "Event Subscription", tab: "workflow" };
  }
  if (query.includes("execution boundaries") || query.includes("boundaries")) {
    return { intent: "Execution Boundaries", tab: "explain" };
  }
  
  if (query.includes("expand architecture") || query.includes("architecture")) {
    return { intent: "Expand Architecture", tab: "explain" };
  }
  if (query.includes("workflows") || query.includes("related workflows")) {
    return { intent: "Related Workflows", tab: "workflow" };
  }
  if (query.includes("flow") || query.includes("verification flow")) {
    return { intent: "Verification Flow", tab: "workflow" };
  }
  
  // Default fallbacks based on quick keywords
  if (query.includes("explain")) {
    return { intent: "Expand Architecture", tab: "explain" };
  }
  if (query.includes("trace") || query.includes("step")) {
    return { intent: "Verification Flow", tab: "workflow" };
  }
  if (query.includes("schema") || query.includes("json")) {
    return { intent: "Contract Structure", tab: "schema" };
  }
  if (query.includes("commands") || query.includes("cli")) {
    return { intent: "Replay Commands", tab: "commands" };
  }
  
  return { intent: "Expand Architecture", tab: "explain" };
}

// Classifies the highlighted entity or matches against local db structure
function getEntityCategory(selectedText, sources) {
  if (!selectedText || !sources || sources.length === 0) return "general";
  const query = selectedText.trim().toLowerCase();
  const primarySource = sources[0];
  const category = primarySource.category || "";
  const tags = primarySource.tags || [];

  if (query.includes("replay_id") || query.includes("snapshot_id") || query.includes("snap_") || query.includes("diff") || query.includes("state_mutation") || category === "replay-diff" || tags.includes("snapshots") || tags.includes("replay")) {
    return "replay";
  }
  if (query.includes("ast") || query.includes("ssrf") || query.includes("sqli") || query.includes("event contract") || query.includes("event_type") || query.includes("event_broker") || category === "findings" || category === "modules" || tags.includes("reentrancy") || tags.includes("event-bus")) {
    return "schema";
  }
  if (query.includes("scapy") || query.includes("npcap") || query.includes("winpcap") || query.includes("sudo") || query.includes("socket") || query.includes("verification_state") || query.includes("finding_id") || category === "getting-started" || tags.includes("cli")) {
    return "cli";
  }
  if (query.includes("pluginmanager") || query.includes("plugin_manager") || query.includes("orchestrator") || query.includes("concurrency") || query.includes("thread") || category === "internals") {
    return "plugin";
  }
  return "general";
}

// Get refinement Action Chips dynamically adapting to entity category
function getChipsForCategory(cat) {
  switch (cat) {
    case "replay":
      return ["Replay Lifecycle", "State Diff", "Snapshot Mapping"];
    case "schema":
      return ["Field Definitions", "Contract Structure", "Payload Mapping"];
    case "cli":
      return ["Related Flags", "Verification Modes", "Replay Commands"];
    case "plugin":
      return ["Registration Flow", "Event Subscription", "Execution Boundaries"];
    default:
      return ["Expand Architecture", "Related Workflows", "Verification Flow", "Related Commands"];
  }
}

export default function AssistantDrawer({ isOpen, onClose, selectedText, initialQuery, pageContent }) {
  const [activeTab, setActiveTab] = useState("explain");
  const [response, setResponse] = useState("");
  const [sources, setSources] = useState([]);
  const [retrievalTier, setRetrievalTier] = useState("Limited Documentation Context");
  const [refinementText, setRefinementText] = useState("");
  const [activeRefinement, setActiveRefinement] = useState("");

  // Semantic query sequence (deterministic synthesis)
  const executeQuery = (text, tabId, refinement) => {
    // 1. Semantic Retrieval: Retrieve relevant doc chunks and evaluate match tier
    const { sources: matchedSources, matchTier } = retrieveDocumentation(text, "", pageContent);
    setSources(matchedSources);
    setRetrievalTier(matchTier);
    
    // 2. Deterministic Synthesis Layer: Dynamic context assembly (zero latency)
    const synthesizedOutput = synthesizeContext({
      selectedText: text,
      activeTab: tabId,
      sources: matchedSources,
      pageContent: pageContent,
      refinementText: refinement
    });
    
    setResponse(synthesizedOutput);
  };

  // Trigger query immediately when drawer opens or variables change
  useEffect(() => {
    if (isOpen && selectedText) {
      const startingTab = initialQuery || "explain";
      setActiveTab(startingTab);
      setRefinementText("");
      setActiveRefinement("");
      executeQuery(selectedText, startingTab, "");
    }
  }, [isOpen, selectedText, initialQuery]);

  // Tab click handler (instant render, zero network delay)
  const handleTabChange = (tabId) => {
    setActiveTab(tabId);
    executeQuery(selectedText, tabId, activeRefinement);
  };

  // Action chip refinement triggers (instant switch to related tab and synthesize)
  const handleChipClick = (chip) => {
    const parsed = parseRefinementIntent(chip);
    setActiveRefinement(chip);
    setRefinementText(chip);
    setActiveTab(parsed.tab);
    executeQuery(selectedText, parsed.tab, chip);
  };

  // Custom refinement form submission
  const handleRefineSubmit = (e) => {
    if (e) e.preventDefault();
    if (!refinementText.trim()) return;
    
    const parsed = parseRefinementIntent(refinementText);
    setActiveRefinement(refinementText);
    setActiveTab(parsed.tab);
    executeQuery(selectedText, parsed.tab, refinementText);
  };

  // Render badge colors strictly based on discrete matching tiers
  const getTierBadgeStyle = () => {
    switch (retrievalTier) {
      case "Strong Retrieval Match":
        return "text-indigo-400 bg-indigo-500/10 border-indigo-950/60";
      case "Medium Retrieval Match":
        return "text-blue-400 bg-blue-500/10 border-blue-950/60";
      case "Weak Retrieval Match":
        return "text-amber-400 bg-amber-500/10 border-amber-950/60";
      case "Contextual Match Available":
        return "text-teal-400 bg-teal-500/10 border-teal-950/60";
      default:
        return "text-zinc-500 bg-zinc-900 border-zinc-800";
    }
  };

  if (!isOpen) return null;

  const tabs = [
    { id: "explain", label: "Explain", icon: Cpu },
    { id: "workflow", label: "Workflow Trace", icon: GitFork },
    { id: "schema", label: "Schema Contract", icon: Database },
    { id: "commands", label: "CLI Recipes", icon: Terminal }
  ];

  // Resolve current active refinement chips
  const entityCategory = getEntityCategory(selectedText, sources);
  const activeChips = getChipsForCategory(entityCategory);

  return (
    <>
      {/* Backdrop overlay */}
      <div 
        onClick={onClose}
        className="fixed inset-0 z-40 bg-black/60 backdrop-blur-xs animate-fadeIn select-none"
      />

      {/* Right Drawer Slide Panel (Expanded width for readability) */}
      <div className="fixed top-0 right-0 z-50 h-full w-full sm:w-[560px] bg-zinc-950 border-l border-zinc-900 shadow-2xl flex flex-col justify-between transition-transform duration-300 ease-out select-text">
        
        {/* Drawer Header */}
        <header className="flex items-center justify-between px-6 py-4.5 border-b border-zinc-900 bg-zinc-950/80 sticky top-0 z-10 select-none">
          <div className="flex items-center gap-2.5 text-zinc-350 font-mono text-[11px] font-bold uppercase tracking-widest">
            <Bookmark size={13} className="text-indigo-500" />
            <span>Semantic Docs Layer</span>
          </div>
          
          <div className="flex items-center gap-4">
            <span className="text-[10px] font-mono text-zinc-500 bg-zinc-900 px-2.5 py-1 rounded border border-zinc-800 font-semibold tracking-wider uppercase">
              Workflow Interpreter
            </span>
            
            <button
              onClick={onClose}
              className="p-1.5 rounded hover:bg-zinc-900 text-zinc-500 hover:text-zinc-300 transition-colors cursor-pointer"
            >
              <X size={15} />
            </button>
          </div>
        </header>

        {/* High-Fidelity Navigation Workspace Tabs */}
        <nav className="flex border-b border-zinc-900 bg-zinc-950 px-4.5 select-none overflow-x-auto scrollbar-none">
          {tabs.map((t) => {
            const Icon = t.icon;
            const isActive = activeTab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => handleTabChange(t.id)}
                className={`flex items-center gap-2 px-4 py-4 border-b-2 text-[11px] sm:text-xs font-mono font-bold tracking-normal transition-all cursor-pointer whitespace-nowrap ${
                  isActive 
                    ? "border-indigo-500 text-indigo-400 bg-zinc-900/10" 
                    : "border-transparent text-zinc-500 hover:text-zinc-350"
                }`}
              >
                <Icon size={13} />
                <span>{t.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Scrollable Workspace */}
        <div className="flex-1 overflow-y-auto p-6 space-y-7">
          
          {/* Highlighted Context Block */}
          {selectedText && (
            <div className="space-y-2.5">
              <span className="text-[10px] sm:text-[11px] font-bold font-mono tracking-widest text-zinc-500 uppercase block select-none">
                Highlighted Context
              </span>
              <div className="border-l-2 border-indigo-500 bg-zinc-900/35 p-4 px-4.5 font-mono text-[13px] sm:text-[14px] leading-6 text-zinc-300 select-text overflow-x-auto break-all rounded-r">
                &ldquo;{selectedText}&rdquo;
              </div>
            </div>
          )}

          {/* Contextual Synthesis View */}
          <div className="space-y-3">
            <div className="flex items-center justify-between select-none">
              <span className="text-[10px] sm:text-[11px] font-bold font-mono tracking-widest text-zinc-500 uppercase block">
                Deterministic Contextual Synthesis
              </span>
              
              {/* Retrieval Match Tier Badge */}
              {response && (
                <span className={`text-[10px] font-mono font-bold uppercase tracking-wide border px-2.5 py-0.5 rounded ${getTierBadgeStyle()}`}>
                  {retrievalTier}
                </span>
              )}
            </div>
            
            {/* Expanded font-size container (text-[15px] and leading-7) */}
            <div className="bg-zinc-950 rounded-lg border border-zinc-900/60 p-6 sm:p-7 font-sans text-[15px] leading-7 text-zinc-350 select-text">
              <div className="space-y-1.5">
                {response ? (
                  renderMarkdown(response)
                ) : (
                  <div className="text-zinc-600 italic select-none">Retrieving technical specs...</div>
                )}
              </div>
            </div>

            {/* Dynamic Contextual Refinement Chips (HIGH PRIORITY) */}
            {activeChips.length > 0 && (
              <div className="flex flex-wrap gap-2 pt-2.5 select-none">
                {activeChips.map((chip) => {
                  const isSelected = activeRefinement === chip;
                  return (
                    <button
                      key={chip}
                      onClick={() => handleChipClick(chip)}
                      className={`px-2.5 py-1 rounded border text-[11px] font-mono transition-all cursor-pointer font-medium ${
                        isSelected
                          ? "bg-indigo-500/10 border-indigo-500/40 text-indigo-400 font-bold"
                          : "bg-zinc-900/50 border-zinc-900 text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200 hover:border-zinc-800"
                      }`}
                    >
                      [{chip}]
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Documentation Anchors */}
          {sources.length > 0 && (
            <div className="space-y-3">
              <span className="text-[10px] sm:text-[11px] font-bold font-mono tracking-widest text-zinc-500 uppercase block select-none">
                Documentation Anchors ({sources.length})
              </span>
              <div className="space-y-2.5 select-none">
                {sources.map((src) => (
                  <Link 
                    key={src.id}
                    href={`/docs#${src.id}`}
                    onClick={onClose}
                    className="group flex items-center justify-between p-3.5 rounded-lg border border-zinc-900 hover:border-zinc-800 bg-zinc-950/40 hover:bg-zinc-900/10 transition-all duration-150 cursor-pointer"
                  >
                    <div>
                      <span className="text-[13px] font-mono font-bold text-zinc-300 group-hover:text-indigo-400 transition-colors block">
                        {src.title}
                      </span>
                      <span className="text-[11px] text-zinc-500 block mt-1 max-w-lg line-clamp-1">
                        {src.content}
                      </span>
                    </div>
                    <ChevronRight size={13} className="text-zinc-600 group-hover:text-zinc-400 group-hover:translate-x-0.5 transition-all" />
                  </Link>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Technical Contextual Refinement Bar (Sleek, desaturated developer input) */}
        <div className="px-6 py-4 border-t border-zinc-900/80 bg-zinc-950 select-none">
          <form onSubmit={handleRefineSubmit} className="relative flex items-center">
            <div className="absolute left-3.5 text-zinc-500">
              <Sliders size={14} className="animate-pulse" />
            </div>
            
            <input
              type="text"
              value={refinementText}
              onChange={(e) => setRefinementText(e.target.value)}
              placeholder="Refine interpretation..."
              className="w-full pl-10 pr-24 py-2.5 rounded bg-zinc-900/40 border border-zinc-900 hover:border-zinc-800 focus:border-indigo-950/80 focus:ring-1 focus:ring-indigo-950/40 text-zinc-250 placeholder-zinc-500 font-mono text-[12px] transition-all outline-none"
            />
            
            <div className="absolute right-2.5 flex items-center gap-2">
              {refinementText && (
                <button
                  type="button"
                  onClick={() => {
                    setRefinementText("");
                    setActiveRefinement("");
                    executeQuery(selectedText, activeTab, "");
                  }}
                  className="px-2 py-1 rounded hover:bg-zinc-900 text-zinc-500 hover:text-zinc-350 text-[10px] font-mono transition-colors cursor-pointer"
                >
                  Clear
                </button>
              )}
              <button
                type="submit"
                className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800 text-zinc-300 hover:text-zinc-100 text-[10px] font-mono transition-all cursor-pointer font-bold"
              >
                Refine
              </button>
            </div>
          </form>
        </div>

        {/* Restrained Panel Footer */}
        <footer className="px-6 py-4.5 border-t border-zinc-900 bg-zinc-950 flex items-center justify-between select-none">
          <div className="flex items-center gap-1.5 text-zinc-650 font-mono text-[9px] uppercase tracking-wider font-medium">
            <span>Retrieval-constrained explanation layer</span>
          </div>
          <span className="text-[9px] font-mono text-zinc-500 bg-zinc-900 px-2.5 py-0.5 rounded border border-zinc-800 font-semibold tracking-wide uppercase">
            100% Offline
          </span>
        </footer>
      </div>
    </>
  );
}
