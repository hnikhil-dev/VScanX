"use client";

import Link from "next/link";
import { useState, useEffect } from "react";
import { Shield, RefreshCw, Layers, CheckCircle2, Sliders, ArrowRight, Code, Play, Terminal } from "lucide-react";

export default function Home() {
  const [activeProofTab, setActiveProofTab] = useState("diff");
  
  // Dynamic Live Scanner Console State
  const [targetInput, setTargetInput] = useState("enterprise-target.io");
  const [profile, setProfile] = useState("web");
  const [terminalLines, setTerminalLines] = useState([]);
  const [isScanning, setIsScanning] = useState(false);

  // Bento Interactive States
  const [bentoActiveDomain, setBentoActiveDomain] = useState(null); 
  
  // Verification Engine State
  const [verifyState, setVerifyState] = useState("idle"); // 'idle', 'probing', 'anomaly', 'verifying', 'confirmed'
  // Replay & Diff State
  const [diffRun, setDiffRun] = useState("run1"); // 'run1' | 'run2'
  // Canonical Findings State
  const [selectedSchema, setSelectedSchema] = useState("idor"); 
  // Event Bus State
  const [eventsFired, setEventsFired] = useState([]);
  
  const getProfileLogs = (target, type) => {
    switch (type) {
      case "web":
        return [
          { text: `$ vscanx scan ${target} --verify`, delay: 100 },
          { text: "[*] Initializing Dynamic Discovery Engine...", delay: 150 },
          { text: "[*] Orchestrator loading verified scan profiles...", delay: 150 },
          { text: "[verified] Open Redirect (Parameter: next=/admin)", color: "text-emerald-400 font-semibold", delay: 350 },
          { text: "[verified] CSP Misconfiguration (Missing unsafe-inline block)", color: "text-emerald-400 font-semibold", delay: 250 },
          { text: "[diff] Security state changed: 2 anomalies verified", color: "text-indigo-400", delay: 300 },
          { text: `[replay] scan_291A snapshot saved. Replay trace available for target ${target}`, color: "text-blue-400", delay: 250 },
          { text: "[success] Scan complete. 0 false positives reported.", color: "text-emerald-400", delay: 150 }
        ];
      case "network":
        return [
          { text: `$ vscanx scan ${target} --scan-type network --verify`, delay: 100 },
          { text: "[*] Scanning active service ports using multi-threaded probes...", delay: 150 },
          { text: "[*] Executing passive TLS/SSL handshake analysis...", delay: 200 },
          { text: "[verified] Crypto TLS Analyzer (A04): Weak cipher suites allowed (3DES/RC4)", color: "text-emerald-400 font-semibold", delay: 350 },
          { text: "[verified] Service Header Disclosure: Apache/2.4.41 exposing patch state", color: "text-emerald-400 font-semibold", delay: 250 },
          { text: "[diff] Network topology state updated. Service mappings verified.", color: "text-indigo-400", delay: 300 },
          { text: `[replay] scan_404C generated. System ports re-scannable.`, color: "text-blue-400", delay: 250 },
          { text: "[success] Network sweep complete.", color: "text-emerald-400", delay: 150 }
        ];
      case "web3":
        return [
          { text: `$ vscanx scan ${target} --scan-type web3 --rpc-url https://eth-mainnet.io --verify`, delay: 100 },
          { text: "[*] Establishing connection with Web3 RPC endpoint...", delay: 150 },
          { text: "[*] Parsing smart contract binary and dynamic function interfaces...", delay: 250 },
          { text: "[verified] Access Control Checker (SC01): Privileged contract function accessible by public", color: "text-emerald-400 font-semibold", delay: 450 },
          { text: "[verified] Reentrancy Analyzer (SC08): Missing state mutations sequence before recursive call", color: "text-emerald-400 font-semibold", delay: 350 },
          { text: "[diff] Cryptographic state mutations validated. 2 severe vectors verified.", color: "text-indigo-400", delay: 300 },
          { text: `[replay] scan_701D generated. Live state replay simulation active.`, color: "text-blue-400", delay: 250 },
          { text: "[success] Smart Contract audit complete.", color: "text-emerald-400", delay: 150 }
        ];
      case "agentic":
        return [
          { text: `$ vscanx scan ${target} --scan-type agentic --verify`, delay: 100 },
          { text: "[*] Injecting specialized LLM alignment bypass test formats...", delay: 150 },
          { text: "[*] Testing sandbox escapes and prompt memory poison hooks...", delay: 200 },
          { text: "[verified] Prompt Injection Fuzzer (ASI01): System instructions successfully bypassed", color: "text-emerald-400 font-semibold", delay: 400 },
          { text: "[verified] Code Execution Prober (ASI05): Sandbox escape via hex escaped commands", color: "text-emerald-400 font-semibold", delay: 300 },
          { text: "[diff] Agent boundary definitions mutated. 2 critical escapes verified.", color: "text-indigo-400", delay: 300 },
          { text: `[replay] scan_991F generated. Prompt payloads cached locally.`, color: "text-blue-400", delay: 250 },
          { text: "[success] Agentic sandbox audit complete.", color: "text-emerald-400", delay: 150 }
        ];
      default:
        return [];
    }
  };

  const handleScanStart = () => {
    if (isScanning) return;
    setIsScanning(true);
    setTerminalLines([]);
    
    const logs = getProfileLogs(targetInput || "enterprise-target.io", profile);
    if (logs.length === 0) {
      setIsScanning(false);
      return;
    }
    
    let currentIdx = 0;
    
    const printLine = () => {
      const lineToAdd = logs[currentIdx];
      setTerminalLines(prev => [...prev, lineToAdd]);
      
      currentIdx++;
      
      if (currentIdx < logs.length) {
        setTimeout(printLine, logs[currentIdx].delay);
      } else {
        setIsScanning(false);
      }
    };
    
    setTimeout(printLine, logs[0].delay);
  };

  // Verification Engine Process Sequence
  const runVerificationProcess = () => {
    setVerifyState("probing");
    setTimeout(() => {
      setVerifyState("anomaly");
      setTimeout(() => {
        setVerifyState("verifying");
        setTimeout(() => {
          setVerifyState("confirmed");
        }, 1500);
      }, 1200);
    }, 1000);
  };

  // Event Bus Action Sequence
  const fireEvent = (moduleName) => {
    const newEvent = {
      id: Date.now(),
      module: moduleName,
      type: moduleName === "web" ? "SSRF_PROBE" : moduleName === "web3" ? "REENTRANCY_DETECTED" : "SANDBOX_ESCAPE",
      timestamp: new Date().toLocaleTimeString()
    };
    setEventsFired(prev => [newEvent, ...prev].slice(0, 4));
  };

  // Run initial scan automatically on mount
  useEffect(() => {
    handleScanStart();
  }, []);

  return (
    <div className="flex flex-col items-center w-full bg-zinc-950 text-zinc-50 min-h-screen">
      
      {/* 1. Hero Section - Fluid layout w-full */}
      <section className="relative w-full px-6 md:px-12 lg:px-24 pt-24 pb-20 text-center flex flex-col items-center">
        {/* Ambient Top Glow */}
        <div className="absolute top-0 left-1/2 -z-10 h-[360px] w-[800px] -translate-x-1/2 rounded-full bg-gradient-to-r from-blue-500/5 to-indigo-500/5 blur-[140px]" />
        
        {/* Product Hunt Featured Badge */}
        <div className="mb-8 z-10 transition-transform duration-200 hover:scale-[1.02]">
          <a 
            href="https://www.producthunt.com/products/vscanx?embed=true&utm_source=badge-featured&utm_medium=badge&utm_campaign=badge-vscanx" 
            target="_blank" 
            rel="noopener noreferrer"
          >
            <img 
              src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=1158035&theme=dark" 
              alt="VScanX - Deterministic security scanner with zero false positives | Product Hunt" 
              width="250" 
              height="54" 
              className="w-[250px] h-[54px] object-contain"
            />
          </a>
        </div>

        <h1 className="w-full text-5xl sm:text-6xl lg:text-7xl font-sans font-bold tracking-tight text-zinc-50 leading-[1.05]">
          Verification-Driven <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-zinc-100 via-zinc-400 to-zinc-600">
            Security Analysis.
          </span>
        </h1>
        
        <p className="mt-8 max-w-3xl text-lg sm:text-xl text-zinc-400 font-sans font-normal leading-relaxed">
          Unifying dynamic scanning capabilities and active payload validation. Eliminate false positives and trace regression states continuously.
        </p>

        {/* Dynamic Scanning target input bar */}
        <div className="mt-12 w-full max-w-4xl rounded-lg border border-zinc-900 bg-zinc-900/40 p-3.5 flex flex-col sm:flex-row items-center gap-4 backdrop-blur-md shadow-2xl transition-all duration-200">
          <div className="flex-1 flex items-center w-full pl-4 gap-3 text-zinc-400">
            <span className="text-sm font-mono text-zinc-500">target:</span>
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="enterprise-target.io"
              className="bg-transparent text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none w-full font-mono font-semibold"
            />
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto shrink-0 border-t sm:border-t-0 sm:border-l border-zinc-800/80 pt-3 sm:pt-0 sm:pl-4">
            <span className="text-xs font-mono text-zinc-500 uppercase">domain:</span>
            <select
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              className="bg-zinc-950/80 border border-zinc-900 rounded px-3 py-1.5 text-sm text-zinc-300 focus:outline-none cursor-pointer font-mono font-semibold"
            >
              <option value="web">Web App</option>
              <option value="network">Network</option>
              <option value="web3">Smart Contracts</option>
              <option value="agentic">Agentic AI</option>
            </select>
          </div>

          <button
            onClick={handleScanStart}
            disabled={isScanning}
            className="w-full sm:w-auto rounded bg-zinc-50 hover:bg-zinc-200 px-6 py-2.5 text-sm font-bold text-zinc-950 flex items-center justify-center gap-2 transition-all duration-150 cursor-pointer active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
          >
            <Play size={14} className={isScanning ? "animate-pulse" : ""} />
            {isScanning ? "Scanning..." : "Execute Scan"}
          </button>
        </div>
      </section>

      {/* 2. Interactive Terminal Console */}
      <section className="w-full px-6 md:px-12 lg:px-24 pb-24 flex flex-col items-center">
        <div className="w-full max-w-6xl rounded-lg border border-zinc-900 bg-zinc-900/40 p-2 shadow-2xl backdrop-blur-sm relative">
          
          {/* Subtle status label */}
          <div className="absolute top-5 right-7 flex items-center gap-2.5">
            <span className={`w-2 h-2 rounded-full ${isScanning ? "bg-amber-400 animate-ping" : "bg-emerald-500"}`} />
            <span className="text-xs font-mono text-zinc-500 uppercase font-semibold">{isScanning ? "Auditing" : "Ready"}</span>
          </div>

          {/* Terminal Title Bar */}
          <div className="flex items-center justify-between px-4 py-2 border-b border-zinc-900 text-zinc-500 font-mono text-xs">
            <div className="flex gap-2">
              <span className="w-3 h-3 rounded-full bg-zinc-800" />
              <span className="w-3 h-3 rounded-full bg-zinc-800" />
              <span className="w-3 h-3 rounded-full bg-zinc-800" />
            </div>
            <span className="font-semibold">vscanx-console</span>
            <div className="w-16" />
          </div>
          
          {/* Terminal Content Area */}
          <div className="min-h-[280px] bg-zinc-950 rounded p-6 font-mono text-sm text-zinc-400 leading-relaxed overflow-x-auto selection:bg-zinc-800 select-none">
            {terminalLines.map((line, i) => line && (
              <div key={i} className={line.color || "text-zinc-300"}>
                {line.text}
              </div>
            ))}
            {isScanning && (
              <span className="inline-block w-2 h-5 bg-zinc-400 cursor-blink ml-0.5 align-middle" />
            )}
          </div>
        </div>
      </section>

      {/* 3. Bento-Box Grid */}
      <section className="w-full px-6 md:px-12 lg:px-24 py-24 border-t border-zinc-900">
        <div className="text-center mb-20">
          <h2 className="text-4xl font-extrabold font-sans tracking-tight text-zinc-50">Core Architectural Differentiators</h2>
          <p className="mt-4 text-zinc-400 text-lg sm:text-xl max-w-3xl mx-auto leading-relaxed">
            Select any layout module below to view live framework execution and dynamic security traces in real-time.
          </p>
        </div>
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Card 1: Verification Engine */}
          <div 
            onClick={() => setBentoActiveDomain("verify")}
            className={`relative rounded-xl border p-8 flex flex-col gap-6 transition-all duration-200 cursor-pointer ${
              bentoActiveDomain === "verify" ? "border-zinc-800 bg-zinc-900/50 shadow-2xl" : "border-zinc-900 bg-zinc-900/30 hover:border-zinc-800 hover:translate-y-[-2px]"
            }`}
          >
            <div className="text-indigo-400 w-12 h-12 flex items-center justify-center rounded-lg bg-indigo-500/10 border border-indigo-500/20 shrink-0">
              <CheckCircle2 size={24} />
            </div>
            <div>
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-extrabold font-sans text-zinc-100">Verification Engine</h3>
                <span className="text-xs font-mono text-indigo-400 bg-indigo-500/10 px-2.5 py-1 rounded font-bold">Active</span>
              </div>
              <p className="mt-4 text-base text-zinc-400 leading-relaxed">
                Separates passive probing steps from active exploit confirmations to ensure verified reliability.
              </p>
            </div>

            {/* Verification Sandbox widget */}
            <div className="mt-4 rounded-lg bg-zinc-950 p-5 border border-zinc-900 font-mono text-sm space-y-4 select-none">
              <div className="flex items-center justify-between text-xs border-b border-zinc-900 pb-2.5 text-zinc-500 font-bold tracking-wider">
                <span>EXECUTION FEEDBACK:</span>
                <span className="uppercase font-extrabold text-zinc-300">{verifyState}</span>
              </div>
              
              {verifyState === "idle" && (
                <button 
                  onClick={(e) => { e.stopPropagation(); runVerificationProcess(); }}
                  className="w-full bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-lg py-2.5 text-xs font-bold transition-colors cursor-pointer"
                >
                  Confirm SSRF Action
                </button>
              )}

              {verifyState === "probing" && (
                <div className="text-zinc-500 text-xs animate-pulse font-medium">
                  [*] Mapping endpoints and query routes...
                </div>
              )}

              {verifyState === "anomaly" && (
                <div className="text-amber-400 text-xs font-medium">
                  [!] Redirect anomaly flagged. Mapped parameter: ?next=/login
                </div>
              )}

              {verifyState === "verifying" && (
                <div className="text-indigo-400 text-xs animate-pulse font-medium">
                  [*] Dispatching active validation check parameters...
                </div>
              )}

              {verifyState === "confirmed" && (
                <div className="space-y-3">
                  <div className="text-emerald-400 font-extrabold text-xs">[VERIFIED] Host verification check completed.</div>
                  <div className="text-zinc-500 text-xs font-medium">Security state updated successfully.</div>
                  <button 
                    onClick={(e) => { e.stopPropagation(); setVerifyState("idle"); }}
                    className="mt-2 w-full bg-zinc-900 hover:bg-zinc-800 text-zinc-300 text-xs rounded-lg py-1.5 cursor-pointer font-bold"
                  >
                    Reset Monitor
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Card 2: Replay & Diff */}
          <div 
            onClick={() => setBentoActiveDomain("diff")}
            className={`relative rounded-xl border p-8 flex flex-col gap-6 transition-all duration-200 cursor-pointer ${
              bentoActiveDomain === "diff" ? "border-zinc-800 bg-zinc-900/50 shadow-2xl" : "border-zinc-900 bg-zinc-900/30 hover:border-zinc-800 hover:translate-y-[-2px]"
            }`}
          >
            <div className="text-blue-400 w-12 h-12 flex items-center justify-center rounded-lg bg-blue-500/10 border border-blue-500/20 shrink-0">
              <RefreshCw size={22} />
            </div>
            <div>
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-extrabold font-sans text-zinc-100">Replay & Diff</h3>
                <span className="text-xs font-mono text-blue-400 bg-blue-500/10 px-2.5 py-1 rounded font-bold">Active</span>
              </div>
              <p className="mt-4 text-base text-zinc-400 leading-relaxed">
                Snapshots state indices across audit runs to detect regression mutations and delta records.
              </p>
            </div>

            {/* Diff Selector Widget */}
            <div className="mt-4 rounded-lg bg-zinc-950 p-5 border border-zinc-900 font-mono text-xs space-y-4 select-none">
              <div className="flex justify-between items-center text-xs border-b border-zinc-900 pb-2.5 text-zinc-500 font-bold tracking-wider">
                <span>SELECT STATE RUN:</span>
                <div className="flex gap-2">
                  <button 
                    onClick={(e) => { e.stopPropagation(); setDiffRun("run1"); }}
                    className={`px-2.5 py-1 rounded border text-xs cursor-pointer font-bold ${diffRun === "run1" ? "border-blue-500 text-blue-400 bg-blue-500/10" : "border-zinc-800 text-zinc-500"}`}
                  >
                    Run 1
                  </button>
                  <button 
                    onClick={(e) => { e.stopPropagation(); setDiffRun("run2"); }}
                    className={`px-2.5 py-1 rounded border text-xs cursor-pointer font-bold ${diffRun === "run2" ? "border-blue-500 text-blue-400 bg-blue-500/10" : "border-zinc-800 text-zinc-500"}`}
                  >
                    Run 2 (Diff)
                  </button>
                </div>
              </div>

              {diffRun === "run1" ? (
                <div className="space-y-1.5 text-zinc-400 text-xs font-medium">
                  {"{"}
                  <div className="pl-4">"target": "target.io",</div>
                  <div className="pl-4 text-zinc-300">"ssl_expired": false,</div>
                  <div className="pl-4 text-zinc-300">"open_redirect": "unverified"</div>
                  {"}"}
                </div>
              ) : (
                <div className="space-y-1.5 text-zinc-400 text-xs font-medium">
                  {"{"}
                  <div className="pl-4">"target": "target.io",</div>
                  <div className="pl-4 text-red-400 bg-red-950/20 font-semibold">- "ssl_expired": false</div>
                  <div className="pl-4 text-emerald-400 bg-emerald-950/20 font-semibold">+ "ssl_expired": true</div>
                  <div className="pl-4 text-emerald-400 bg-emerald-950/20 font-semibold">+ "open_redirect": "verified"</div>
                  {"}"}
                </div>
              )}
            </div>
          </div>

          {/* Card 3: Canonical Findings */}
          <div 
            onClick={() => setBentoActiveDomain("findings")}
            className={`relative rounded-xl border p-8 flex flex-col gap-6 transition-all duration-200 cursor-pointer ${
              bentoActiveDomain === "findings" ? "border-zinc-800 bg-zinc-900/50 shadow-2xl" : "border-zinc-900 bg-zinc-900/30 hover:border-zinc-800 hover:translate-y-[-2px]"
            }`}
          >
            <div className="text-zinc-300 w-12 h-12 flex items-center justify-center rounded-lg bg-zinc-850 border border-zinc-700/30 shrink-0">
              <Shield size={22} />
            </div>
            <div>
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-extrabold font-sans text-zinc-100">Canonical Findings</h3>
                <span className="text-xs font-mono text-zinc-300 bg-zinc-800 px-2.5 py-1 rounded font-bold">Active</span>
              </div>
              <p className="mt-4 text-base text-zinc-400 leading-relaxed">
                Aggregates verified threat items into a standardized validation JSON output formats.
              </p>
            </div>

            {/* Schema Toggle Widget */}
            <div className="mt-4 rounded-lg bg-zinc-950 p-5 border border-zinc-900 font-mono text-xs space-y-4 select-none">
              <div className="flex justify-between items-center text-xs border-b border-zinc-900 pb-2.5 text-zinc-500 font-bold tracking-wider">
                <span>NORMALIZE SCHEMA:</span>
                <select 
                  value={selectedSchema} 
                  onChange={(e) => { e.stopPropagation(); setSelectedSchema(e.target.value); }}
                  className="bg-zinc-900 border border-zinc-800 rounded-lg text-xs text-zinc-200 cursor-pointer px-2 py-1 focus:outline-none font-bold"
                >
                  <option value="idor">IDOR (Web)</option>
                  <option value="sqli">SQLi (Web)</option>
                  <option value="injection">Prompt (AI)</option>
                </select>
              </div>

              {selectedSchema === "idor" && (
                <div className="text-xs text-zinc-300 space-y-1.5 font-medium">
                  <div>"signature": "IDOR",</div>
                  <div>"confidence": "high",</div>
                  <div className="text-indigo-400 font-bold">"status": "VERIFIED"</div>
                </div>
              )}

              {selectedSchema === "sqli" && (
                <div className="text-xs text-zinc-300 space-y-1.5 font-medium">
                  <div>"signature": "SQL Injection",</div>
                  <div>"confidence": "high",</div>
                  <div className="text-indigo-400 font-bold">"status": "VERIFIED"</div>
                </div>
              )}

              {selectedSchema === "injection" && (
                <div className="text-xs text-zinc-300 space-y-1.5 font-medium">
                  <div>"signature": "Prompt Injection Escape",</div>
                  <div>"confidence": "critical",</div>
                  <div className="text-indigo-400 font-bold">"status": "VERIFIED"</div>
                </div>
              )}
            </div>
          </div>

          {/* Card 4: Event Bus */}
          <div 
            onClick={() => setBentoActiveDomain("events")}
            className={`relative rounded-xl border p-8 flex flex-col gap-6 lg:col-span-2 transition-all duration-200 cursor-pointer ${
              bentoActiveDomain === "events" ? "border-zinc-800 bg-zinc-900/50 shadow-2xl" : "border-zinc-900 bg-zinc-900/30 hover:border-zinc-800 hover:translate-y-[-2px]"
            }`}
          >
            <div className="text-zinc-350 w-12 h-12 flex items-center justify-center rounded-lg bg-zinc-850 border border-zinc-700/30 shrink-0">
              <Layers size={22} />
            </div>
            <div>
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-extrabold font-sans text-zinc-100">Typed Event Contracts</h3>
                <span className="text-xs font-mono text-zinc-300 bg-zinc-800 px-2.5 py-1 rounded font-bold">Active</span>
              </div>
              <p className="mt-4 text-base text-zinc-400 leading-relaxed">
                Connects independent module run stages asynchronously using dedicated broadcast event buses.
              </p>
            </div>

            {/* Event Dispatcher Pulse Dashboard */}
            <div className="mt-4 rounded-lg bg-zinc-950 p-5 border border-zinc-900 font-mono text-xs space-y-4 select-none">
              <div className="flex items-center justify-between text-xs border-b border-zinc-900 pb-2.5 text-zinc-500 font-bold tracking-wider">
                <span>EVENT ROUTING SYSTEM:</span>
                <span className="text-indigo-400 uppercase font-extrabold">Trace channel live</span>
              </div>

              <div className="flex flex-wrap gap-3">
                <button 
                  onClick={(e) => { e.stopPropagation(); fireEvent("web"); }}
                  className="flex-1 bg-zinc-900 hover:bg-zinc-805 border border-zinc-800 text-xs rounded-lg py-2 cursor-pointer text-zinc-200 text-center font-bold"
                >
                  SSRF Event
                </button>
                <button 
                  onClick={(e) => { e.stopPropagation(); fireEvent("web3"); }}
                  className="flex-1 bg-zinc-900 hover:bg-zinc-805 border border-zinc-800 text-xs rounded-lg py-2 cursor-pointer text-zinc-200 text-center font-bold"
                >
                  Contract Event
                </button>
                <button 
                  onClick={(e) => { e.stopPropagation(); fireEvent("ai"); }}
                  className="flex-1 bg-zinc-900 hover:bg-zinc-805 border border-zinc-800 text-xs rounded-lg py-2 cursor-pointer text-zinc-200 text-center font-bold"
                >
                  AI Boundary Event
                </button>
              </div>

              <div className="space-y-2 mt-4">
                {eventsFired.length === 0 ? (
                  <div className="text-xs text-zinc-600 text-center py-3 font-medium">Click a button above to broadcast an active threat state event...</div>
                ) : (
                  eventsFired.map(ev => (
                    <div key={ev.id} className="flex justify-between items-center text-xs bg-zinc-900/50 px-3.5 py-1.5 rounded-lg border border-zinc-900 text-zinc-350 animate-fade-in font-medium">
                      <span>[{ev.timestamp}] <span className="text-indigo-400 font-bold">{ev.module.toUpperCase()}</span>: {ev.type}</span>
                      <span className="text-emerald-400 font-extrabold">ROUTE DISPATCHED</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Card 5: Low-Noise Verification */}
          <div 
            onClick={() => setBentoActiveDomain("noise")}
            className={`relative rounded-xl border p-8 flex flex-col gap-6 transition-all duration-200 cursor-pointer ${
              bentoActiveDomain === "noise" ? "border-zinc-800 bg-zinc-900/50 shadow-2xl" : "border-zinc-900 bg-zinc-900/30 hover:border-zinc-800 hover:translate-y-[-2px]"
            }`}
          >
            <div className="text-zinc-300 w-12 h-12 flex items-center justify-center rounded-lg bg-zinc-855 border border-zinc-700/30 shrink-0">
              <Sliders size={22} />
            </div>
            <div>
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-extrabold font-sans text-zinc-100">Low-Noise Verification</h3>
                <span className="text-xs font-mono text-zinc-300 bg-zinc-800 px-2.5 py-1 rounded font-bold">Active</span>
              </div>
              <p className="mt-4 text-base text-zinc-400 leading-relaxed">
                Maintains transparent debug exception logging to ensure scan accuracy.
              </p>
            </div>

            {/* Exception trace details */}
            <div className="mt-4 rounded-lg bg-zinc-950 p-5 border border-zinc-900 font-mono text-xs space-y-4 select-none">
              <div className="flex justify-between items-center text-xs border-b border-zinc-900 pb-2.5 text-zinc-500 font-bold tracking-wider">
                <span>STACK COVERAGE:</span>
                <span className="text-zinc-400 font-extrabold">MUTATIONS</span>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-xs bg-red-950/10 text-red-400 border border-red-900/30 px-3.5 py-1.5 rounded-lg font-medium">
                  <span>try/except: pass</span>
                  <span className="font-bold">B110 Silent</span>
                </div>
                <div className="flex justify-between text-xs bg-emerald-950/10 text-emerald-400 border border-emerald-900/30 px-3.5 py-1.5 rounded-lg font-medium">
                  <span>logger.debug(err)</span>
                  <span className="font-bold">100% Verified</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 4. Proof Sections - Fluid Layout */}
      <section className="w-full px-6 md:px-12 lg:px-24 py-20 border-t border-zinc-900 flex flex-col items-center">
        <div className="text-center mb-12">
          <h2 className="text-2xl font-bold font-sans tracking-tight text-zinc-50">Security State Verification Records</h2>
          <p className="mt-3 text-zinc-400 text-sm max-w-xl">Inspect live structural outputs of comparative state reports and Normalized Findings.</p>
        </div>

        {/* Tab Controls */}
        <div className="flex border-b border-zinc-900 w-full max-w-lg justify-center mb-8">
          <button 
            onClick={() => setActiveProofTab("diff")}
            className={`px-6 py-3.5 text-sm font-bold border-b transition-colors flex items-center gap-2 cursor-pointer ${activeProofTab === "diff" ? "border-indigo-500 text-zinc-50 font-bold" : "border-transparent text-zinc-500 hover:text-zinc-300"}`}
          >
            <RefreshCw size={14} />
            Comparative Run State Diff
          </button>
          <button 
            onClick={() => setActiveProofTab("json")}
            className={`px-6 py-3.5 text-sm font-bold border-b transition-colors flex items-center gap-2 cursor-pointer ${activeProofTab === "json" ? "border-indigo-500 text-zinc-50 font-bold" : "border-transparent text-zinc-500 hover:text-zinc-300"}`}
          >
            <Code size={14} />
            Canonical Findings JSON Schema
          </button>
        </div>

        {/* Tab Display Container */}
        <div className="w-full max-w-5xl rounded-lg border border-zinc-900 bg-zinc-950 p-5 font-mono text-sm text-zinc-400 leading-relaxed overflow-x-auto min-h-[240px]">
          {activeProofTab === "diff" ? (
            <pre className="text-left text-zinc-500 selection:bg-zinc-800">
              <span className="text-zinc-650"># vscanx diff scan_291A scan_291B</span>{"\n"}
              {"{\n"}
              {"  \"target\": \"target.com\",\n"}
              {"  \"comparative_deltas\": [\n"}
              {"    {\n"}
              {"      \"module\": \"modules.web.http_redirect\",\n"}
              <span className="text-red-400 bg-red-950/20 w-full block">-     \"state\": \"unverified\",</span>
              <span className="text-emerald-400 bg-emerald-950/20 w-full block">+     \"state\": \"verified\",</span>
              <span className="text-emerald-400 bg-emerald-950/20 w-full block">+     \"verification_payload\": \"/admin?next=https://malicious.com\",</span>
              <span className="text-emerald-400 bg-emerald-950/20 w-full block">+     \"verified_timestamp\": \"2026-05-27T13:08:50Z\"</span>
              {"    }\n"}
              {"  ]\n"}
              {"}"}
            </pre>
          ) : (
            <pre className="text-left text-zinc-400 selection:bg-zinc-800">
              {"{\n"}
              {"  \"finding_id\": \"CAN-2026-F981\",\n"}
              {"  \"signature\": \"Open Redirect Vulnerability\",\n"}
              {"  \"module\": \"modules.web.http_redirect\",\n"}
              {"  \"confidence\": \"high\",\n"}
              {"  \"verification\": {\n"}
              {"    \"status\": \"VERIFIED\",\n"}
              {"    \"proof\": {\n"}
              {"      \"request\": \"GET /admin?next=http%3A%2F%2Fgoogle.com\",\n"}
              {"      \"response_headers\": {\n"}
              {"        \"location\": \"http://google.com\",\n"}
              {"        \"status_code\": 302\n"}
              {"      }\n"}
              {"    }\n"}
              {"  }\n"}
              {"}"}
            </pre>
          )}
        </div>
      </section>
    </div>
  );
}
