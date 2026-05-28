"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { 
  Play, Terminal, Sliders, Layers, Shield, 
  CheckCircle2, RefreshCw, Cpu, Copy, Check, Info, ChevronDown, ChevronUp 
} from "lucide-react";
import { demoTargets } from "./datasets";

export default function SandboxPage() {
  const [selectedTarget, setSelectedTarget] = useState(demoTargets[0]);
  const [selectedWorkflow, setSelectedWorkflow] = useState(demoTargets[0].workflows[0]);
  
  // Toggles for Flags
  const [flagVerify, setFlagVerify] = useState(true);
  const [flagVerbose, setFlagVerbose] = useState(false);
  const [flagOffline, setFlagOffline] = useState(false);
  
  // Simulator State
  const [isScanning, setIsScanning] = useState(false);
  const [terminalLines, setTerminalLines] = useState([]);
  const [activeStep, setActiveStep] = useState(-1); // -1: Idle, 0-5 mapping to visualization steps
  
  // UI copy helpers
  const [copiedJSON, setCopiedJSON] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);
  
  // Collapsible inline trace details
  const [expandedTraceStep, setExpandedTraceStep] = useState(null); // 'trace' | 'code' | null
  
  const terminalEndRef = useRef(null);

  // Sync selected target changes
  const handleTargetChange = (targetId) => {
    const target = demoTargets.find(t => t.id === targetId);
    if (target) {
      setSelectedTarget(target);
      setSelectedWorkflow(target.workflows[0]);
      setTerminalLines([]);
      setIsScanning(false);
      setActiveStep(-1);
      setExpandedTraceStep(null);
    }
  };

  // Sync selected workflow changes
  const handleWorkflowChange = (workflow) => {
    setSelectedWorkflow(workflow);
    setTerminalLines([]);
    setIsScanning(false);
    setActiveStep(-1);
    setExpandedTraceStep(null);
  };

  // Run the simulation workflow
  const runSimulation = () => {
    if (isScanning) return;
    
    setIsScanning(true);
    setTerminalLines([]);
    setActiveStep(-1);
    setExpandedTraceStep(null);
    
    const logs = selectedWorkflow.logs;
    let index = 0;
    
    const printLine = () => {
      if (index >= logs.length) {
        setIsScanning(false);
        // Expand the critical verification step inline automatically upon completion to reveal code artifact
        setExpandedTraceStep("verify");
        return;
      }
      
      const currentLog = logs[index];
      setTerminalLines(prev => [...prev, currentLog]);
      
      // Map log state to visual pipeline steps in real-time
      if (currentLog.text.includes("$ vscanx")) {
        setActiveStep(0); 
      } else if (currentLog.text.includes("signature match") || currentLog.text.includes("AST match") || currentLog.text.includes("Prompt bypass")) {
        setActiveStep(0); // Probing
      } else if (currentLog.text.includes("[event]")) {
        setActiveStep(1); // Event Dispatch
      } else if (currentLog.text.includes("container") || currentLog.text.includes("RPC fork") || currentLog.text.includes("gVisor")) {
        setActiveStep(2); // Sandbox Spawn
      } else if (currentLog.text.includes("[verified]") || currentLog.text.includes("exploit contract") || currentLog.text.includes("escape commands")) {
        setActiveStep(3); // Exploit Verification
      } else if (currentLog.text.includes("[success]") || currentLog.text.includes("[diff]")) {
        setActiveStep(4); // Report / Complete
      }
      
      index++;
      setTimeout(printLine, currentLog.delay || 200);
    };
    
    printLine();
  };

  // Copy JSON payload
  const handleCopyJSON = () => {
    navigator.clipboard.writeText(JSON.stringify(selectedWorkflow.findings, null, 2));
    setCopiedJSON(true);
    setTimeout(() => setCopiedJSON(false), 2000);
  };

  // Copy python verification code snippet
  const handleCopyCode = () => {
    navigator.clipboard.writeText(selectedWorkflow.verificationTrace.code);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  // Autoscroll terminal screen internally
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [terminalLines]);

  return (
    <div className="w-full max-w-[1500px] mx-auto bg-zinc-950 text-zinc-50 min-h-screen py-16 px-6 md:px-12 lg:px-16 scroll-smooth select-text">
      
      {/* ---------------- SECTION 1: HEADER & TARGET SELECTION ---------------- */}
      <section className="w-full mb-16 space-y-8">
        <div className="flex items-center gap-3 text-indigo-400 font-mono text-sm tracking-widest font-bold uppercase select-none">
          <Cpu size={18} />
          <span>Interactive Sandbox</span>
        </div>
        
        <h1 className="text-5xl md:text-6xl lg:text-7xl font-sans font-extrabold tracking-tight text-zinc-50 leading-[1.05]">
          Understanding Workflows <br />
          Through Direct Simulation.
        </h1>
        
        <p className="text-xl text-zinc-400 leading-relaxed font-sans max-w-5xl">
          This system behaves like an interactive technical article. Instead of a noisy security dashboard, 
          you will scroll through a progressive chronological narrative showing how VScanX coordinates signature discovery, 
          decoupled event-dispatching, local sandbox spawns, and state-evolution checks.
        </p>

        <div className="pt-6 w-full">
          <div className="rounded-xl border border-zinc-900 bg-zinc-950/40 p-8 md:p-10 space-y-8 w-full">
            <header className="select-none border-b border-zinc-900 pb-5">
              <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-zinc-400">
                01 / Choose Simulation Target
              </h3>
              <p className="text-xs sm:text-sm text-zinc-500 mt-2">Select one of our pre-configured environments below to initialize the workflow state.</p>
            </header>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full">
              {demoTargets.map((target) => (
                <button
                  key={target.id}
                  disabled={isScanning}
                  onClick={() => handleTargetChange(target.id)}
                  className={`p-6 md:p-8 rounded-lg text-left transition-all duration-150 flex flex-col justify-between h-48 border ${
                    selectedTarget.id === target.id
                      ? "bg-zinc-900 border-zinc-700 text-zinc-100 shadow-xl"
                      : "bg-zinc-950 border-zinc-900 hover:border-zinc-800 text-zinc-400 hover:text-zinc-200 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
                  }`}
                >
                  <span className="text-sm font-mono font-bold block">{target.name}</span>
                  <span className="text-xs sm:text-sm text-zinc-500 font-sans leading-relaxed block mt-3 line-clamp-4">
                    {target.description}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ---------------- SECTION 2: WORKFLOW & CLI CONFIG ---------------- */}
      <section className="w-full mb-16">
        <div className="rounded-xl border border-zinc-900 bg-zinc-950/40 p-8 md:p-10 space-y-10 w-full">
          <header className="select-none border-b border-zinc-900 pb-5">
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-zinc-400">
              02 / Configure Security Profile & Arguments
            </h3>
            <p className="text-xs sm:text-sm text-zinc-500 mt-2">Choose the specific CLI workflow template and toggle optional validation flags.</p>
          </header>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
            {/* Workflow List */}
            <div className="space-y-4">
              <span className="text-xs font-bold font-mono tracking-widest text-zinc-500 block uppercase select-none">
                Workflow Blueprints
              </span>
              <div className="space-y-3">
                {selectedTarget.workflows.map((workflow) => (
                  <button
                    key={workflow.id}
                    disabled={isScanning}
                    onClick={() => handleWorkflowChange(workflow)}
                    className={`w-full flex items-center justify-between px-5 py-4 rounded border text-left transition-all duration-150 ${
                      selectedWorkflow.id === workflow.id
                        ? "bg-zinc-900 border-zinc-700 text-zinc-100"
                        : "bg-zinc-950/60 border-zinc-900 hover:bg-zinc-900/40 text-zinc-400 hover:text-zinc-200 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
                    }`}
                  >
                    <div>
                      <span className="text-sm font-mono font-bold block">{workflow.name}</span>
                      <span className="text-xs text-zinc-500 block mt-1 line-clamp-1">
                        {workflow.description}
                      </span>
                    </div>
                    {selectedWorkflow.id === workflow.id && (
                      <span className="w-2 h-2 rounded-full bg-indigo-400 shrink-0" />
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* CLI Command Builder & Flags */}
            <div className="space-y-6">
              <span className="text-xs font-bold font-mono tracking-widest text-zinc-500 block uppercase select-none">
                Parameter Toggles
              </span>
              
              <div className="space-y-3.5 font-mono text-sm text-zinc-400 select-none">
                <label className="flex items-center gap-4 hover:text-zinc-200 cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={flagVerify} 
                    onChange={(e) => setFlagVerify(e.target.checked)}
                    disabled={isScanning}
                    className="accent-indigo-500 border-zinc-900 rounded bg-zinc-950 w-4 h-4 cursor-pointer disabled:opacity-50"
                  />
                  <span>--verify <span className="text-zinc-500 font-sans text-xs">(safe active validation check)</span></span>
                </label>
                
                <label className="flex items-center gap-4 hover:text-zinc-200 cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={flagVerbose} 
                    onChange={(e) => setFlagVerbose(e.target.checked)}
                    disabled={isScanning}
                    className="accent-indigo-500 border-zinc-900 rounded bg-zinc-950 w-4 h-4 cursor-pointer disabled:opacity-50"
                  />
                  <span>--verbose <span className="text-zinc-500 font-sans text-xs">(detailed telemetry output)</span></span>
                </label>

                <label className="flex items-center gap-4 hover:text-zinc-200 cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={flagOffline} 
                    onChange={(e) => setFlagOffline(e.target.checked)}
                    disabled={isScanning}
                    className="accent-indigo-500 border-zinc-900 rounded bg-zinc-950 w-4 h-4 cursor-pointer disabled:opacity-50"
                  />
                  <span>--offline-mode <span className="text-zinc-500 font-sans text-xs">(isolate sandbox loopback)</span></span>
                </label>
              </div>

              {/* Real Command String Preview */}
              <div className="bg-zinc-950 rounded border border-zinc-900 p-5 font-mono text-sm text-zinc-200 font-semibold select-all break-all leading-normal">
                $ {selectedWorkflow.command}
                {flagVerify && " --verify"}
                {flagVerbose && " --verbose"}
                {flagOffline && " --offline-mode"}
              </div>
            </div>
          </div>

          <div className="pt-6 flex flex-col md:flex-row items-center justify-between gap-6 border-t border-zinc-900">
            <span className="text-xs md:text-sm text-zinc-500 font-sans leading-relaxed max-w-2xl">
              * Click "Execute Workflow Simulation" to trigger the real-time vertical compilation pipeline.
            </span>
            <button
              onClick={runSimulation}
              disabled={isScanning}
              className="w-full md:w-auto rounded bg-zinc-50 hover:bg-zinc-200 px-8 py-3.5 text-sm font-bold text-zinc-950 flex items-center justify-center gap-2.5 transition-all duration-150 cursor-pointer active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed shrink-0 select-none"
            >
              <Play size={14} className={isScanning ? "animate-pulse" : ""} />
              {isScanning ? "Simulating Workflow..." : "Execute Workflow Simulation"}
            </button>
          </div>
        </div>
      </section>

      {/* ---------------- SECTION 3: VERTICAL CHRONOLOGICAL LIFECYCLE ---------------- */}
      <section className="w-full mb-16 space-y-8">
        <header className="select-none border-b border-zinc-900 pb-5">
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-zinc-400">
            03 / Chronological Workflow Pipeline
          </h3>
          <p className="text-xs sm:text-sm text-zinc-500 mt-2">
            Watch the lifecycle progression in real-time. Direct operational data, event payloads, and code classes are revealed inline as stages trigger.
          </p>
        </header>

        {/* Chronological Vertical List */}
        <div className="relative border-l border-zinc-900 ml-6 pl-10 py-2 space-y-10 font-sans w-full">
          
          {/* Step 1: Passive Probing */}
          <div className="relative space-y-5 w-full">
            <div className={`absolute left-0 -translate-x-[53px] top-1 w-8 h-8 rounded-full flex items-center justify-center border font-mono text-xs font-bold transition-all duration-200 ${
              isScanning && activeStep === 0 ? "bg-indigo-950 text-indigo-400 border-indigo-500 scale-105" :
              activeStep >= 0 ? "bg-emerald-950 text-emerald-400 border-emerald-500" :
              "bg-zinc-950 text-zinc-600 border-zinc-900"
            }`}>
              {activeStep >= 0 && !isScanning ? <Check size={12} className="font-bold" /> : "1"}
            </div>

            <div className="flex justify-between items-center">
              <h4 className={`text-base md:text-lg font-mono font-bold transition-colors ${
                isScanning && activeStep === 0 ? "text-indigo-400" : activeStep >= 0 ? "text-zinc-200" : "text-zinc-500"
              }`}>
                Passive Discovery & Detection
              </h4>
              {isScanning && activeStep === 0 && (
                <span className="text-xs font-mono text-indigo-400 bg-indigo-500/10 px-3 py-1 rounded uppercase font-bold animate-pulse">Running</span>
              )}
            </div>
            
            <p className={`text-sm sm:text-base leading-relaxed max-w-4xl transition-colors ${activeStep >= 0 ? "text-zinc-400" : "text-zinc-600"}`}>
              {selectedTarget.id === "demo-web-app" && "SSRF detector walks loopback paths checking metadata resolves."}
              {selectedTarget.id === "demo-rpc-node" && "Smart contract abstract syntax tree parser registers missing states in transfer functions."}
              {selectedTarget.id === "demo-agent-sandbox" && "LLM interface prober maps alignment parameters for instruction escape vectors."}
            </p>

            {/* PROGRESSIVE DETAIL INLINE: Probing Output details */}
            {activeStep >= 0 && (
              <div className="bg-zinc-950 border border-zinc-900/60 p-6 rounded-lg text-sm text-zinc-400 font-mono space-y-2 animate-fadeIn w-full">
                <span className="text-zinc-500 block border-b border-zinc-900 pb-2 mb-2 uppercase font-bold text-xs tracking-wider">Passive Probe Hit Details</span>
                <div>Target probed: <span className="text-zinc-300 font-semibold">{selectedTarget.name}.local</span></div>
                {selectedTarget.id === "demo-web-app" && (
                  <>
                    <div>Signature Class: <span className="text-zinc-300">modules/web/ssrf_detector.py</span></div>
                    <div>Heuristic Threshold: <span className="text-emerald-400 font-bold">MATCH (leaked route resolution candidate)</span></div>
                  </>
                )}
                {selectedTarget.id === "demo-rpc-node" && (
                  <>
                    <div>Signature Class: <span className="text-zinc-300">modules/web3/reentrancy_analyzer.py</span></div>
                    <div>Heuristic Threshold: <span className="text-emerald-400 font-bold">MATCH (state update missing before call)</span></div>
                  </>
                )}
                {selectedTarget.id === "demo-agent-sandbox" && (
                  <>
                    <div>Signature Class: <span className="text-zinc-300">modules/ai/prompt_fuzzer.py</span></div>
                    <div>Heuristic Threshold: <span className="text-emerald-400 font-bold">MATCH (base instructions bypassed)</span></div>
                  </>
                )}
              </div>
            )}
          </div>

          {/* Step 2: Event Dispatch */}
          <div className="relative space-y-5 w-full">
            <div className={`absolute left-0 -translate-x-[53px] top-1 w-8 h-8 rounded-full flex items-center justify-center border font-mono text-xs font-bold transition-all duration-200 ${
              isScanning && activeStep === 1 ? "bg-indigo-950 text-indigo-400 border-indigo-500 scale-105" :
              activeStep >= 1 ? "bg-emerald-950 text-emerald-400 border-emerald-500" :
              "bg-zinc-950 text-zinc-600 border-zinc-900"
            }`}>
              {activeStep >= 1 && !isScanning ? <Check size={12} className="font-bold" /> : "2"}
            </div>

            <div className="flex justify-between items-center">
              <h4 className={`text-base md:text-lg font-mono font-bold transition-colors ${
                isScanning && activeStep === 1 ? "text-indigo-400" : activeStep >= 1 ? "text-zinc-200" : "text-zinc-500"
              }`}>
                Decoupled Event Dispatching
              </h4>
              {isScanning && activeStep === 1 && (
                <span className="text-xs font-mono text-indigo-400 bg-indigo-500/10 px-3 py-1 rounded uppercase font-bold animate-pulse">Routing</span>
              )}
            </div>

            <p className={`text-sm sm:text-base leading-relaxed max-w-4xl transition-colors ${activeStep >= 1 ? "text-zinc-400" : "text-zinc-600"}`}>
              Light probes bypass direct testing. Discovered anomaly parameters are published as typed contracts to the central, decoupled event broker.
            </p>

            {/* PROGRESSIVE DETAIL INLINE: Event payload JSON */}
            {activeStep >= 1 && (
              <div className="bg-zinc-950 border border-zinc-900/60 p-6 rounded-lg text-sm text-zinc-400 font-mono space-y-3 animate-fadeIn select-text w-full">
                <span className="text-zinc-500 block border-b border-zinc-900 pb-2 uppercase font-bold text-xs tracking-wider">Decoupled Event Contract Payload</span>
                <pre className="text-indigo-300 text-xs sm:text-sm overflow-x-auto whitespace-pre font-semibold leading-relaxed">
                  {selectedTarget.id === "demo-web-app" ? 
`{
  "event_id": "evt_web_89127b",
  "topic": "SSRF_PROBE_ANOMALY",
  "timestamp": "2026-05-27T22:42:01Z",
  "payload": {
    "target": "demo-web-app",
    "route": "/api/v1/resolve",
    "param": "url"
  }
}` : selectedTarget.id === "demo-rpc-node" ? 
`{
  "event_id": "evt_web3_71092a",
  "topic": "REENTRANCY_DETECTED",
  "timestamp": "2026-05-27T22:46:22Z",
  "payload": {
    "target": "demo-rpc-node",
    "contract": "0x8920...291a",
    "trigger_block": 18402911
  }
}` : 
`{
  "event_id": "evt_ai_9918c",
  "topic": "SANDBOX_ESCAPE_ANOMALY",
  "timestamp": "2026-05-27T22:49:10Z",
  "payload": {
    "target": "demo-agent-sandbox",
    "chat_route": "/api/v1/agent/chat",
    "suggested_breakout_mode": "gvisor_escape"
  }
}`}
                </pre>
              </div>
            )}
          </div>

          {/* Step 3: Sandbox Spawn */}
          <div className="relative space-y-5 w-full">
            <div className={`absolute left-0 -translate-x-[53px] top-1 w-8 h-8 rounded-full flex items-center justify-center border font-mono text-xs font-bold transition-all duration-200 ${
              isScanning && activeStep === 2 ? "bg-indigo-950 text-indigo-400 border-indigo-500 scale-105" :
              activeStep >= 2 ? "bg-emerald-950 text-emerald-400 border-emerald-500" :
              "bg-zinc-950 text-zinc-600 border-zinc-900"
            }`}>
              {activeStep >= 2 && !isScanning ? <Check size={12} className="font-bold" /> : "3"}
            </div>

            <div className="flex justify-between items-center">
              <h4 className={`text-base md:text-lg font-mono font-bold transition-colors ${
                isScanning && activeStep === 2 ? "text-indigo-400" : activeStep >= 2 ? "text-zinc-200" : "text-zinc-500"
              }`}>
                Ephemeral Sandbox Containment
              </h4>
              {isScanning && activeStep === 2 && (
                <span className="text-xs font-mono text-indigo-400 bg-indigo-500/10 px-3 py-1 rounded uppercase font-bold animate-pulse">Spawning</span>
              )}
            </div>

            <p className={`text-sm sm:text-base leading-relaxed max-w-4xl transition-colors ${activeStep >= 2 ? "text-zinc-400" : "text-zinc-600"}`}>
              The orchestrator catches the event and spins up an isolated, ephemeral sandbox environment to validate the exploit safely without host pollution.
            </p>

            {/* PROGRESSIVE DETAIL INLINE: Container telemetry trace */}
            {activeStep >= 2 && (
              <div className="bg-zinc-950 border border-zinc-900/60 p-6 rounded-lg text-sm text-zinc-400 font-mono space-y-3 animate-fadeIn w-full">
                <div className="flex justify-between items-center border-b border-zinc-900 pb-2 select-none">
                  <span className="text-zinc-500 uppercase font-bold text-xs tracking-wider">Sandbox Container Telemetry Logs</span>
                  <button 
                    onClick={() => setExpandedTraceStep(expandedTraceStep === "trace" ? null : "trace")}
                    className="text-xs text-indigo-400 hover:text-indigo-300 font-bold flex items-center gap-1 cursor-pointer"
                  >
                    {expandedTraceStep === "trace" ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                    {expandedTraceStep === "trace" ? "Hide" : "Show Full Logs"}
                  </button>
                </div>
                
                {/* Collapsible log preview */}
                <div className={`overflow-x-auto whitespace-pre transition-all duration-300 ${expandedTraceStep === "trace" ? "max-h-[300px]" : "max-h-[80px]"}`}>
                  <code className="text-zinc-500 leading-normal text-xs sm:text-sm whitespace-pre block select-text">
                    {selectedWorkflow.verificationTrace.logs}
                  </code>
                </div>
              </div>
            )}
          </div>

          {/* Step 4: Active Exploit Verification */}
          <div className="relative space-y-5 w-full">
            <div className={`absolute left-0 -translate-x-[53px] top-1 w-8 h-8 rounded-full flex items-center justify-center border font-mono text-xs font-bold transition-all duration-200 ${
              isScanning && activeStep === 3 ? "bg-indigo-950 text-indigo-400 border-indigo-500 scale-105" :
              activeStep >= 3 ? "bg-emerald-950 text-emerald-400 border-emerald-500" :
              "bg-zinc-950 text-zinc-600 border-zinc-900"
            }`}>
              {activeStep >= 3 && !isScanning ? <Check size={12} className="font-bold" /> : "4"}
            </div>

            <div className="flex justify-between items-center">
              <h4 className={`text-base md:text-lg font-mono font-bold transition-colors ${
                isScanning && activeStep === 3 ? "text-indigo-400" : activeStep >= 3 ? "text-zinc-200" : "text-zinc-500"
              }`}>
                Dynamic Exploit Verification Check
              </h4>
              {isScanning && activeStep === 3 && (
                <span className="text-xs font-mono text-indigo-400 bg-indigo-500/10 px-3 py-1 rounded uppercase font-bold animate-pulse">Exploiting</span>
              )}
            </div>

            <p className={`text-sm sm:text-base leading-relaxed max-w-4xl transition-colors ${activeStep >= 3 ? "text-zinc-400" : "text-zinc-600"}`}>
              Inside the container workspace, the validator injects verification payloads against loopback interfaces. A vulnerability is verified strictly upon successful execution proof.
            </p>

            {/* PROGRESSIVE DETAIL INLINE: Validation python class code block */}
            {activeStep >= 3 && (
              <div className="bg-zinc-950 border border-zinc-900/60 p-6 rounded-lg text-sm text-zinc-400 font-mono space-y-4 animate-fadeIn w-full">
                <div className="flex justify-between items-center border-b border-zinc-900 pb-2 select-none">
                  <span className="text-zinc-500 uppercase font-bold text-xs tracking-wider">Active Python Verification Class Block</span>
                  <div className="flex gap-6">
                    <button
                      onClick={handleCopyCode}
                      className="text-xs text-zinc-450 hover:text-zinc-200 flex items-center gap-1.5 cursor-pointer font-bold"
                    >
                      {copiedCode ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                      {copiedCode ? "Copied" : "Copy Code"}
                    </button>
                    <button 
                      onClick={() => setExpandedTraceStep(expandedTraceStep === "verify" ? null : "verify")}
                      className="text-xs text-indigo-400 hover:text-indigo-300 font-bold flex items-center gap-1 cursor-pointer"
                    >
                      {expandedTraceStep === "verify" ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                      {expandedTraceStep === "verify" ? "Hide" : "Expand Code"}
                    </button>
                  </div>
                </div>

                <div className={`overflow-hidden transition-all duration-300 ${expandedTraceStep === "verify" ? "max-h-[450px] overflow-y-auto" : "max-h-[100px]"}`}>
                  <pre className="text-zinc-400 leading-normal text-xs sm:text-sm select-text font-semibold">
                    {selectedWorkflow.verificationTrace.code}
                  </pre>
                </div>
              </div>
            )}
          </div>

          {/* Step 5: Report compilation */}
          <div className="relative space-y-5 w-full">
            <div className={`absolute left-0 -translate-x-[53px] top-1 w-8 h-8 rounded-full flex items-center justify-center border font-mono text-xs font-bold transition-all duration-200 ${
              isScanning && activeStep === 4 ? "bg-indigo-950 text-indigo-400 border-indigo-500 scale-105" :
              activeStep >= 4 ? "bg-emerald-950 text-emerald-400 border-emerald-500" :
              "bg-zinc-950 text-zinc-600 border-zinc-900"
            }`}>
              {activeStep >= 4 && !isScanning ? <Check size={12} className="font-bold" /> : "5"}
            </div>

            <div className="flex justify-between items-center">
              <h4 className={`text-base md:text-lg font-mono font-bold transition-colors ${
                isScanning && activeStep === 4 ? "text-indigo-400" : activeStep >= 4 ? "text-zinc-200" : "text-zinc-500"
              }`}>
                Canonical report Output
              </h4>
              {isScanning && activeStep === 4 && (
                <span className="text-xs font-mono text-indigo-400 bg-indigo-500/10 px-3 py-1 rounded uppercase font-bold animate-pulse">Compiling</span>
              )}
            </div>

            <p className={`text-sm sm:text-base leading-relaxed max-w-4xl transition-colors ${activeStep >= 4 ? "text-zinc-400" : "text-zinc-600"}`}>
              The verified exploit details are structured into a deterministic findings record contract and mapped as baseline snapshot targets.
            </p>

            {activeStep >= 4 && !isScanning && (
              <div className="bg-emerald-950/20 border border-emerald-900/60 p-5 rounded-lg text-sm sm:text-base text-emerald-400 font-bold flex items-center gap-3 animate-fadeIn select-none w-full">
                <CheckCircle2 size={18} className="shrink-0" />
                <span>Verification cycle complete. 100% confidence security findings serialized below.</span>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* ---------------- SECTION 4: CLI CONSOLE EVIDENCE (LOW DOMINANCE) ---------------- */}
      <section className="w-full mb-16 space-y-5">
        <header className="select-none border-b border-zinc-900 pb-3">
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-zinc-400">
            04 / CLI Console Telemetry
          </h3>
          <p className="text-xs sm:text-sm text-zinc-500 mt-2">Secondary logs validating standard Unix terminal execution details.</p>
        </header>

        {/* Minimal compact terminal */}
        <div className="rounded-lg border border-zinc-900/60 bg-zinc-950 p-1 shadow-md w-full">
          {/* Subtle tab header bar */}
          <div className="flex items-center justify-between px-4 py-2 border-b border-zinc-900 font-mono text-xs text-zinc-500 select-none">
            <div className="flex gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-zinc-800" />
              <span className="w-2.5 h-2.5 rounded-full bg-zinc-800" />
              <span className="w-2.5 h-2.5 rounded-full bg-zinc-800" />
            </div>
            <span>vscanx-cli-logs</span>
            <div className="w-12" />
          </div>
          
          <div className="bg-zinc-950 p-6 font-mono text-xs sm:text-sm leading-relaxed text-zinc-500 max-h-[220px] overflow-y-auto select-text w-full">
            {terminalLines.length === 0 && (
              <div className="text-zinc-750 italic select-none">Console idle. Execute command in Section 2 to populate trace evidence.</div>
            )}
            {terminalLines.map((line, i) => (
              <div key={i} className={`mb-1 font-semibold ${
                line.type === "input" ? "text-zinc-350 font-bold" :
                line.type === "success" ? "text-emerald-500/90 font-bold" :
                line.type === "event" ? "text-indigo-400/90" :
                line.type === "replay" ? "text-blue-400/90" :
                line.type === "diff" ? "text-purple-400/90 font-bold" :
                "text-zinc-600"
              }`}>
                {line.text}
              </div>
            ))}
            {isScanning && (
              <span className="inline-block w-2 h-4 bg-zinc-650 cursor-blink ml-0.5 align-middle animate-pulse" />
            )}
            <div ref={terminalEndRef} />
          </div>
        </div>
      </section>

      {/* ---------------- SECTION 5: CANONICAL FINDINGS JSON ---------------- */}
      {activeStep >= 4 && !isScanning && (
        <section className="w-full mb-16 space-y-5 animate-fadeIn">
          <header className="flex items-center justify-between border-b border-zinc-900 pb-4">
            <div>
              <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-zinc-400">
                05 / Serialized Findings Output
              </h3>
              <p className="text-xs sm:text-sm text-zinc-500 mt-2">Unified findings contract including proof verification and replay snapshots.</p>
            </div>
            
            <button
              onClick={handleCopyJSON}
              className="text-xs font-mono font-bold text-zinc-200 hover:text-zinc-50 flex items-center gap-2 cursor-pointer bg-zinc-900 px-4 py-2 rounded border border-zinc-800 transition-all select-none"
            >
              {copiedJSON ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
              {copiedJSON ? "Copied Payload" : "Copy findings JSON"}
            </button>
          </header>

          <div className="bg-zinc-950 border border-zinc-900 p-8 rounded-lg overflow-x-auto select-all max-h-[500px] overflow-y-auto w-full">
            <pre className="text-zinc-450 font-mono text-xs sm:text-sm leading-relaxed font-bold">
              {JSON.stringify(selectedWorkflow.findings, null, 2)}
            </pre>
          </div>
        </section>
      )}

      {/* ---------------- SECTION 6: REPLAY & DIFF VISUALIZATION ---------------- */}
      {activeStep >= 4 && !isScanning && selectedWorkflow.id === "diff" && (
        <section className="w-full mb-16 space-y-8 animate-fadeIn">
          <header className="select-none border-b border-zinc-900 pb-3">
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-zinc-400">
              06 / State Evolution Diff visualization
            </h3>
            <p className="text-xs sm:text-sm text-zinc-500 mt-2">Structural differences comparing vulnerability states between scan runs.</p>
          </header>

          <div className="rounded-xl border border-zinc-900 bg-zinc-950/40 p-8 space-y-8 w-full">
            {/* Meta tags */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 select-none w-full">
              {Object.entries(selectedWorkflow.findings.state_meta).map(([key, val]) => (
                <div key={key} className="bg-zinc-950 border border-zinc-900 p-4 rounded font-mono text-center">
                  <span className="text-[10px] uppercase tracking-wider text-zinc-500 block font-bold">{key.replace("_", " ")}</span>
                  <span className="text-sm font-extrabold text-zinc-350 block mt-1.5">{val}</span>
                </div>
              ))}
            </div>

            {/* Diff details */}
            <div className="space-y-4 font-sans w-full">
              {selectedWorkflow.findings.diff_summary.map((item) => {
                const isResolved = item.status_transition.includes("RESOLVED");
                return (
                  <div 
                    key={item.finding_id} 
                    className="rounded-lg border border-zinc-900 bg-zinc-950/80 p-6 space-y-4 text-xs sm:text-sm w-full"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-xs font-bold text-zinc-500">{item.finding_id}</span>
                        <span className="font-mono font-bold text-zinc-200 text-sm sm:text-base">{item.vulnerability}</span>
                      </div>
                      <span className={`font-mono text-xs font-bold px-3 py-1 rounded uppercase tracking-wider ${
                        isResolved ? "bg-emerald-950 text-emerald-400 border border-emerald-900" : "bg-amber-950 text-amber-400 border border-amber-900"
                      }`}>
                        {item.status_transition}
                      </span>
                    </div>
                    <p className="text-xs sm:text-sm text-zinc-400 leading-relaxed font-sans pl-3 border-l border-zinc-900">
                      <strong className="text-zinc-300 font-bold block mb-1">Mitigation Evidence:</strong>
                      {item.mitigation_evidence}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>
        </section>
      )}

      {/* ---------------- SECTION 7: ARCHITECTURAL EXPLANATION ---------------- */}
      <section className="w-full space-y-8 pt-12 border-t border-zinc-900">
        <header className="select-none">
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-zinc-400 mb-2">
            07 / Architectural Verification Mechanics
          </h3>
          <p className="text-base md:text-lg text-zinc-400 leading-relaxed font-sans max-w-4xl">
            How decoupled sandbox engines achieve mathematical reproducibility.
          </p>
        </header>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-10 text-xs sm:text-sm text-zinc-400 leading-relaxed font-sans w-full">
          <div className="space-y-4">
            <h4 className="font-mono font-bold text-zinc-200 text-sm sm:text-base">Systems as Evolving Security States</h4>
            <p>
              VScanX operates on the core thesis that security is not a static audit list, but an evolving state machine. 
              Instead of scattering loose output files across your disk, VScanX structures baseline runs as immutable state snapshot records (`scan_291A`).
            </p>
            <p>
              When a subsequent mitigation check is initiated, the state diff engine directly evaluates transaction pathways and loopback requests on container replicas, identifying the precise delta shift (e.g. `ACTIVE ➔ RESOLVED`).
            </p>
          </div>
          
          <div className="space-y-4">
            <h4 className="font-mono font-bold text-zinc-200 text-sm sm:text-base">Decoupled Containment Boundaries</h4>
            <p>
              To execute exploit scripts with zero false-positives and absolute host protection, VScanX abstracts the verification process entirely. 
              Lightweight detection modules strictly write zero network payloads to live target networks.
            </p>
            <p>
              Instead, they emit typed contracts (such as `REENTRANCY_DETECTED`). The orchestrator intercepts these events, dynamically mapping gVisor sandboxes or EVM RPC block forks to safely run simulated attack scripts inside isolated loopback containers.
            </p>
          </div>
        </div>
      </section>

    </div>
  );
}
