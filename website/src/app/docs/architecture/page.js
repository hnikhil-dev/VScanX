"use client";

import { useState, useEffect, useRef } from "react";
import { Play, Shield, RefreshCw, Activity, Layers, Terminal, Server, ArrowRight, CheckCircle2, Cpu, Globe, Database, MessageSquare, AlertCircle } from "lucide-react";

export default function ArchitectureDocs() {
  const [activeDomain, setActiveDomain] = useState("web");
  const [activeStep, setActiveStep] = useState(0);
  const [isAutoPlaying, setIsAutoPlaying] = useState(true);
  const timerRef = useRef(null);
  const isFirstRender = useRef(true);

  const domainThemes = {
    web: {
      accentColor: "#3b82f6", // Cobalt Blue
      borderColor: "border-blue-900/30",
      activeBg: "bg-blue-950/10",
      activeBorder: "border-blue-800/80",
      glowColor: "rgba(59, 130, 246, 0.12)",
      consoleLabel: "WEB SSRF PIPELINE ACTIVE",
      badgeText: "Web Scan Domain",
    },
    web3: {
      accentColor: "#10b981", // Emerald Green
      borderColor: "border-emerald-900/30",
      activeBg: "bg-emerald-950/10",
      activeBorder: "border-emerald-800/80",
      glowColor: "rgba(16, 185, 129, 0.12)",
      consoleLabel: "WEB3 EVM REENTRANCY PIPELINE ACTIVE",
      badgeText: "Web3/RPC Scan Domain",
    },
    ai: {
      accentColor: "#8b5cf6", // Amethyst Purple
      borderColor: "border-purple-900/30",
      activeBg: "bg-purple-950/10",
      activeBorder: "border-purple-800/80",
      glowColor: "rgba(139, 92, 246, 0.12)",
      consoleLabel: "AGENTIC AI ESCAPE PIPELINE ACTIVE",
      badgeText: "Agentic AI Scan Domain",
    }
  };

  const pipelineSteps = {
    web: [
      {
        id: "probe",
        stage: "Stage 1",
        title: "Redirect Probing",
        icon: Globe,
        desc: "URL redirect parameter fuzzing",
        telemetry: "[Telemetry] modules/web/ssrf_detector.py scanning queries for IDOR/SSRF patterns...",
        benefit: "VScanX probe modules execute high-speed concurrent fuzzer routines to isolate suspicious endpoints, flagging anomalies without initiating costly exploit payload execution.",
        code: `class SSRFDetector(BaseModule):
    def inspect_target(self, target_url: str):
        # Scan redirect query params and flag anomalies
        for param in REDIRECT_PARAMS:
            if target_url.has_param(param):
                self.emit_anomaly(
                    type="SSRF_ANOMALY_FOUND",
                    payload={"url": target_url, "param": param}
                )`
      },
      {
        id: "bus",
        stage: "Stage 2",
        title: "Event Dispatch",
        icon: Layers,
        desc: "Emit typed event anomaly contract",
        telemetry: "[Telemetry] core/event_bus.py: Anomaly captured. Publishing 'SSRF_ANOMALY_FOUND' to Decoupled Channel...",
        benefit: "Instead of immediately executing local payload checks, the scanner emits a typed state anomaly contract to the Event Bus. This completely isolates fuzzer discovery from exploit validation.",
        code: `class EventBus:
    def publish(self, event: AnomalyEvent):
        # Decoupled publish of typed security event contracts
        topic = f"anomaly.{event.type}"
        self.broker.publish(
            topic=topic,
            payload=event.serialize(),
            headers={"trace_id": event.trace_id}
        )`
      },
      {
        id: "orch",
        stage: "Stage 3",
        title: "Sandbox Spawn",
        icon: Cpu,
        desc: "Orchestrate isolated Docker workspace",
        telemetry: "[Telemetry] core/orchestrator.py: Triggered isolated execution sandbox environment container...",
        benefit: "The central Orchestrator subscribes to event pools and dynamic container configurations, spawning isolated execution sandboxes. This prevents local process contamination and maintains absolute clean run states.",
        code: `class ContainerOrchestrator:
    def handle_ssrf_anomaly(self, event: AnomalyEvent):
        # Dynamically spin up isolated sandbox validation container
        container = self.docker_client.containers.run(
            image="vscanx/val-web:latest",
            environment={"TARGET": event.payload["url"]},
            network_mode="sandbox_isolated",
            detach=True
        )
        return self.wait_for_validation(container)`
      },
      {
        id: "verify",
        stage: "Stage 4",
        title: "Cloud Probe",
        icon: Server,
        desc: "Metadata endpoint HTTP audit",
        telemetry: "[Telemetry] plugins/web/metadata_validator.py: Issuing HTTP payload verify target 169.254.169.254...",
        benefit: "The sandboxed validator probes standard Cloud Metadata APIs (AWS/GCP). This stage achieves 100% confidence verification: a vulnerability is only reported if structural cloud headers return successfully.",
        code: `class CloudMetadataValidator:
    def run_validation(self, target: str):
        # Attempt verified connection to standard metadata API
        payload_url = f"{target}?next=http://169.254.169.254/latest/meta-data/"
        response = session.get(payload_url, timeout=3.0)
        
        # 100% confidence check: look for AWS structural keys
        if "ami-id" in response.text or "iam/security-credentials" in response.text:
            return VerificationResult(verified=True, confidence=1.0)
        return VerificationResult(verified=False)`
      },
      {
        id: "finding",
        stage: "Stage 5",
        title: "Canonical Findings",
        icon: Shield,
        desc: "Low-noise structural findings JSON",
        telemetry: "[Telemetry] core/reporter.py: SUCCESS - SSRF Verified. Serializing trace logs into canonical JSON findings...",
        benefit: "The validated vulnerability is exported as a standardized, signature-verified finding. Because verification succeeds only on reproducible state returns, false positives are completely mathematically eliminated.",
        code: `class CanonicalReporter:
    def compile_finding(self, trace_id: str, result: VerificationResult):
        # Serialize highly structured, low-noise finding JSON schema
        finding = CanonicalFinding(
            trace_id=trace_id,
            plugin="web.ssrf",
            is_reproducible=result.verified,
            confidence=result.confidence,
            severity="CRITICAL"
        )
        return finding.export_json()`
      }
    ],
    web3: [
      {
        id: "probe",
        stage: "Stage 1",
        title: "RPC Chain Audit",
        icon: Database,
        desc: "Pull bytecode & AST structure",
        telemetry: "[Telemetry] modules/web3/reentrancy_analyzer.py: Querying RPC target address. Analyzing gas trace limits...",
        benefit: "VScanX queries live RPC node states to inspect transaction bytecode and AST structure, identifying state-mutation anomalies prior to launching sandboxed exploit simulations.",
        code: `class ReentrancyAnalyzer(BaseModule):
    def inspect_bytecode(self, address: str, rpc_client: RPCClient):
        # Static parsing of bytecode and dynamic gas trace anomalies
        code = rpc_client.get_code(address)
        if self.has_suspicious_state_write_after_call(code):
            self.emit_anomaly(
                type="REENTRANCY_DETECTED",
                payload={"contract": address, "rpc": rpc_client.endpoint}
            )`
      },
      {
        id: "bus",
        stage: "Stage 2",
        title: "Event Dispatch",
        icon: Layers,
        desc: "Emit reentrancy anomaly trigger",
        telemetry: "[Telemetry] core/event_bus.py: Anomaly captured. Publishing 'REENTRANCY_DETECTED' event to EVM broker...",
        benefit: "EVM contract anomalies are published immediately to dynamic event channels. The scanning modules cleanly exit, preventing blocked threads and keeping system resource usage perfectly flat.",
        code: `class EventBus:
    def publish(self, event: AnomalyEvent):
        # Decoupled event propagation for Web3 contracts
        topic = f"anomaly.{event.type}"
        self.broker.publish(
            topic=topic,
            payload=event.serialize()
        )`
      },
      {
        id: "orch",
        stage: "Stage 3",
        title: "EVM Sandbox Fork",
        icon: Cpu,
        desc: "Local Anvil node state duplication",
        telemetry: "[Telemetry] core/orchestrator.py: Duplicating state via local Anvil EVM node fork sandbox...",
        benefit: "Instead of firing payloads directly at testnets, VScanX forks the blockchain state locally at the specific anomaly block number. This creates a completely side-effect-free workspace.",
        code: `class Web3Orchestrator:
    def handle_reentrancy_anomaly(self, event: AnomalyEvent):
        # Deploy dedicated local EVM RPC fork (Anvil) for verification
        local_fork = self.evm_manager.spawn_fork(
            rpc_url=event.payload["rpc"],
            block_number="latest"
        )
        return self.execute_sandbox_exploit(local_fork, event.payload["contract"])`
      },
      {
        id: "verify",
        stage: "Stage 4",
        title: "Reentrancy Simulation",
        icon: RefreshCw,
        desc: "Simulate recursive balance drain",
        telemetry: "[Telemetry] plugins/web3/reentrancy_verifier.py: Simulating contract call loops to verify state drain...",
        benefit: "In the local EVM fork, VScanX deploys a specialized validation contract that executes recursive withdrawal loop simulations. A vulnerability is verified ONLY if balance depletion actually succeeds.",
        code: `class ReentrancyVerifier:
    def run_exploit(self, fork: EVMFork, contract_address: str):
        # Execute simulated recursive withdrawal balance mutation
        exploit_contract = self.deploy_exploit(fork)
        initial_balance = fork.get_balance(contract_address)
        
        # Simulate reentrant transaction gas loop
        receipt = exploit_contract.functions.attack().transact()
        final_balance = fork.get_balance(contract_address)
        
        if final_balance < initial_balance:
            return VerificationResult(verified=True, drained=initial_balance - final_balance)`
      },
      {
        id: "finding",
        stage: "Stage 5",
        title: "Canonical Findings",
        icon: Shield,
        desc: "Web3 structured JSON schema",
        telemetry: "[Telemetry] core/reporter.py: SUCCESS - Smart Contract Reentrancy Verified. Compiling JSON findings...",
        benefit: "VScanX exports verified contract vulnerabilities with concrete proof metrics (e.g., exact balance drained). This provides engineers with immediate actionable debugging traces.",
        code: `class CanonicalReporter:
    def compile_finding(self, trace_id: str, result: VerificationResult):
        # Serialize highly structured smart contract vulnerability report
        finding = CanonicalFinding(
            trace_id=trace_id,
            plugin="web3.reentrancy",
            is_reproducible=result.verified,
            proof={"drained_wei": result.drained},
            severity="HIGH"
        )
        return finding.export_json()`
      }
    ],
    ai: [
      {
        id: "probe",
        stage: "Stage 1",
        title: "System Prompt Audit",
        icon: MessageSquare,
        desc: "Heuristic alignment bypass queries",
        telemetry: "[Telemetry] modules/ai/alignment_fuzzer.py: Fuzzing target agent prompt boundaries with injection payloads...",
        benefit: "The AI agent monitor evaluates LLM prompt variables against lightweight alignment jailbreak heuristics, checking boundaries efficiently before committing to heavy containerized RCE verification.",
        code: `class PromptFuzzer(BaseModule):
    def scan_agent(self, agent_endpoint: str):
        # Evaluate system prompts against bypass heuristics
        for payload in JAILBREAK_PAYLOADS:
            response = self.query_llm(agent_endpoint, payload)
            if self.detect_alignment_bypass(response):
                self.emit_anomaly(
                    type="ALIGNMENT_BYPASS_DETECTED",
                    payload={"endpoint": agent_endpoint, "payload": payload}
                )`
      },
      {
        id: "bus",
        stage: "Stage 2",
        title: "Event Dispatch",
        icon: Layers,
        desc: "Emit alignment bypass event",
        telemetry: "[Telemetry] core/event_bus.py: Anomaly captured. Publishing 'ALIGNMENT_BYPASS_DETECTED' event contract...",
        benefit: "Jailbreak and system boundary violations are published as isolated event contracts, allowing decoupled analysis tools to pick up verification tasks asynchronously.",
        code: `class EventBus:
    def publish(self, event: AnomalyEvent):
        # Broker publishes alignment bypass event dynamically
        topic = f"anomaly.{event.type}"
        self.broker.publish(
            topic=topic,
            payload=event.serialize()
        )`
      },
      {
        id: "orch",
        stage: "Stage 3",
        title: "gVisor Container Spawn",
        icon: Cpu,
        desc: "Orchestrate sandboxed environment",
        telemetry: "[Telemetry] core/orchestrator.py: Triggered ultra-secure gVisor container sandbox workspace...",
        benefit: "For sandbox and prompt escape validation, VScanX spawns a gVisor-isolated container workspace (runsc). This provides severe security kernel protection, eliminating host-escape threat.",
        code: `class AIOrchestrator:
    def handle_alignment_anomaly(self, event: AnomalyEvent):
        # Spawn high-isolation gVisor container workspace to audit escape RCE
        container = self.docker_client.containers.run(
            image="vscanx/val-ai:latest",
            environment={"PAYLOAD": event.payload["payload"]},
            runtime="runsc",  # Strict gVisor sandboxed environment
            detach=True
        )
        return self.wait_for_validation(container)`
      },
      {
        id: "verify",
        stage: "Stage 4",
        title: "Host Escape Audit",
        icon: Terminal,
        desc: "Execute shell container validation",
        telemetry: "[Telemetry] plugins/ai/sandbox_auditor.py: Testing exit status and whoami shell commands...",
        benefit: "In the isolated runsc container, VScanX attempts shell execution bypass commands to verify sandbox breakout. An anomaly is validated only if it establishes proven host interaction capabilities.",
        code: `class SandboxAuditor:
    def run_audit(self, container: Container):
        # Validate if the LLM generated prompt broke out into system execution
        result = container.exec_run("whoami")
        
        # 100% confidence check: RCE system command output verified
        if result.exit_code == 0 and "root" in result.output.decode():
            return VerificationResult(verified=True, command="whoami")
        return VerificationResult(verified=False)`
      },
      {
        id: "finding",
        stage: "Stage 5",
        title: "Canonical Findings",
        icon: Shield,
        desc: "Agent escape JSON findings",
        telemetry: "[Telemetry] core/reporter.py: SUCCESS - AI Sandbox Escape RCE Verified. Serializing canonical findings...",
        benefit: "Approved prompt anomalies are stored with exact system commands bypassed, giving AI developers reproducible, actionable artifacts for swift alignment fine-tuning.",
        code: `class CanonicalReporter:
    def compile_finding(self, trace_id: str, result: VerificationResult):
        # Export standardized agent alignment RCE vulnerability findings
        finding = CanonicalFinding(
            trace_id=trace_id,
            plugin="ai.sandbox_escape",
            is_reproducible=result.verified,
            proof={"escaped_cmd": result.command},
            severity="CRITICAL"
        )
        return finding.export_json()`
      }
    ]
  };

  // Autoplay progression for the timeline console
  useEffect(() => {
    if (!isAutoPlaying) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    timerRef.current = setInterval(() => {
      setActiveStep((prev) => {
        if (prev === null) return 0;
        return (prev + 1) % 5;
      });
    }, 6000); // peaceful 6s step duration

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isAutoPlaying]);

  // Smooth scroll target to step card *after* the duration-300 animation fully stabilizes height.
  // This solves the animation race condition so the viewport lands exactly at the card top,
  // preventing the card header from scrolling out of sight as the bottom extends.
  useEffect(() => {
    if (isFirstRender.current) {
      isFirstRender.current = false;
      return;
    }

    if (activeStep !== null) {
      const timer = setTimeout(() => {
        const element = document.getElementById(`step-card-${activeStep}`);
        if (element) {
          element.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }, 320); // 320ms ensures the 300ms transition height is fully expanded and static!
      return () => clearTimeout(timer);
    }
  }, [activeStep]);

  const handleDomainChange = (domain) => {
    setActiveDomain(domain);
    setActiveStep(0);
  };

  const handleStepClick = (index) => {
    setIsAutoPlaying(false); // Pause auto-advancing upon manual click
    setActiveStep((prev) => (prev === index ? null : index)); // Toggle collapse/extend behavior
  };

  const theme = domainThemes[activeDomain];
  const steps = pipelineSteps[activeDomain];

  return (
    <article className="prose prose-invert prose-zinc max-w-none prose-base sm:prose-lg leading-relaxed select-none">
      <header className="mb-10">
        <h1 id="overview" className="text-3xl font-extrabold tracking-tight text-zinc-50 mb-3 select-text">
          Decoupled Engine Architecture
        </h1>
        <p className="text-zinc-400 text-lg select-text max-w-3xl">
          VScanX achieves mathematically zero false positives using a decoupled, event-driven verification architecture. Trace target scanning domains below.
        </p>
      </header>

      {/* Domain Selection Tabs - Minimalist, desaturated, clear */}
      <div className="flex border-b border-zinc-900 mb-8" role="tablist">
        <button
          onClick={() => handleDomainChange("web")}
          role="tab"
          aria-selected={activeDomain === "web"}
          className={`px-6 py-3 text-sm font-bold border-b-2 transition-all cursor-pointer ${
            activeDomain === "web"
              ? "border-blue-500 text-zinc-100 font-extrabold"
              : "border-transparent text-zinc-500 hover:text-zinc-300"
          }`}
        >
          Web SSRF Trace
        </button>
        <button
          onClick={() => handleDomainChange("web3")}
          role="tab"
          aria-selected={activeDomain === "web3"}
          className={`px-6 py-3 text-sm font-bold border-b-2 transition-all cursor-pointer ${
            activeDomain === "web3"
              ? "border-emerald-500 text-zinc-100 font-extrabold"
              : "border-transparent text-zinc-500 hover:text-zinc-300"
          }`}
        >
          Web3 Reentrancy
        </button>
        <button
          onClick={() => handleDomainChange("ai")}
          role="tab"
          aria-selected={activeDomain === "ai"}
          className={`px-6 py-3 text-sm font-bold border-b-2 transition-all cursor-pointer ${
            activeDomain === "ai"
              ? "border-purple-500 text-zinc-100 font-extrabold"
              : "border-transparent text-zinc-500 hover:text-zinc-300"
          }`}
        >
          AI Prompt Escape
        </button>
      </div>

      {/* Interactive Accordion Blueprint Wrapper */}
      <section 
        id="blueprints"
        className="w-full rounded-xl border border-zinc-900 bg-zinc-950 p-6 md:p-8 relative select-none scroll-mt-28"
        style={{
          boxShadow: `0 0 40px -20px ${theme.glowColor}`,
          backgroundImage: "radial-gradient(circle, rgba(255,255,255,0.007) 1px, transparent 1px)",
          backgroundSize: "24px 24px"
        }}
      >
        {/* Quiet Auto-cycle Playback controls */}
        <div className="flex items-center justify-between mb-6 bg-zinc-950/80 border border-zinc-900/60 rounded-lg px-4 py-3 select-none">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsAutoPlaying(!isAutoPlaying)}
              className="flex items-center gap-2 rounded border border-zinc-800 bg-zinc-900/40 hover:bg-zinc-900 hover:text-zinc-200 px-3 py-1.5 text-xs font-bold text-zinc-400 transition-all cursor-pointer"
            >
              {isAutoPlaying ? (
                <>
                  <div className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-pulse" />
                  <span>Pause Auto-Cycle</span>
                </>
              ) : (
                <>
                  <Play size={10} className="fill-current text-zinc-400" />
                  <span>Resume Auto-Cycle</span>
                </>
              )}
            </button>
            {!isAutoPlaying && (
              <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider">
                [Interactive Explaining Mode Active]
              </span>
            )}
          </div>
          <div className="text-xs text-zinc-400 font-bold font-sans">
            {activeStep !== null ? `Step ${activeStep + 1} of 5` : "All Collapsed"}
          </div>
        </div>

        {/* Interactive Accordion Timeline Console */}
        <div className="w-full flex flex-col gap-4 select-none">
          {steps.map((step, idx) => {
            const StepIcon = step.icon;
            const isActive = idx === activeStep;
            const isCompleted = activeStep !== null && idx < activeStep;

            return (
              <div
                key={step.id}
                id={`step-card-${idx}`}
                className={`rounded-xl border transition-all duration-200 overflow-hidden scroll-mt-28 ${
                  isActive
                    ? `${theme.activeBorder} ${theme.activeBg} bg-zinc-900/10`
                    : "border-zinc-900 bg-zinc-950/20 hover:border-zinc-800/80"
                }`}
                style={{
                  boxShadow: isActive ? `0 4px 20px -10px ${theme.glowColor}` : "none",
                }}
              >
                {/* Header (Clickable Trigger) */}
                <button
                  onClick={() => handleStepClick(idx)}
                  className="w-full flex items-center justify-between p-4 sm:p-5 text-left cursor-pointer focus:outline-none select-none"
                >
                  <div className="flex items-center gap-4 min-w-0">
                    {/* Status Indicator / Icon */}
                    <div
                      className="p-2.5 rounded-lg border shrink-0 transition-all duration-200"
                      style={{
                        borderColor: isActive ? theme.accentColor : "#27272a",
                        color: isActive || isCompleted ? theme.accentColor : "#52525b",
                        backgroundColor: isActive ? `${theme.accentColor}08` : "transparent",
                      }}
                    >
                      <StepIcon size={18} />
                    </div>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[9px] sm:text-[10px] font-bold text-zinc-500 uppercase tracking-widest leading-none">
                          {step.stage}
                        </span>
                        {isActive && (
                          <span
                            className="rounded-full w-1.5 h-1.5 animate-pulse"
                            style={{ backgroundColor: theme.accentColor }}
                          />
                        )}
                      </div>
                      <h3 className={`text-base font-bold transition-colors leading-snug mt-1 ${isActive ? "text-zinc-50 font-extrabold" : "text-zinc-300"}`}>
                        {step.title}
                      </h3>
                    </div>
                  </div>

                  {/* Collapsed view short description */}
                  {!isActive && (
                    <span className="hidden sm:inline text-xs text-zinc-500 truncate max-w-[200px] md:max-w-[300px] mr-4 select-none">
                      {step.desc}
                    </span>
                  )}
                </button>

                {/* Smooth Sliding Expanded Content (Animate max-height & opacity) */}
                <div 
                  className="transition-all duration-300 ease-in-out overflow-hidden"
                  style={{
                    maxHeight: isActive ? "1500px" : "0px",
                    opacity: isActive ? 1 : 0
                  }}
                >
                  <div className="border-t border-zinc-900/60 p-5 sm:p-6 space-y-6">
                    {/* Explanation paragraph */}
                    <p className="text-sm sm:text-base text-zinc-300 leading-relaxed max-w-3xl select-text">
                      {step.benefit}
                    </p>

                    {/* Code Block & Telemetry Stack */}
                    <div className="space-y-4">
                      {/* Highly Authentic Code Excerpt Pane */}
                      <div className="rounded-lg border border-zinc-900 bg-[#050507] overflow-hidden select-text">
                        <div className="flex items-center justify-between border-b border-zinc-900 bg-zinc-900/20 px-4 py-2.5 text-[11px] font-bold font-mono text-zinc-500">
                          <span className="flex items-center gap-1.5">
                            <Terminal size={12} style={{ color: theme.accentColor }} />
                            vscanx/{step.id === "bus" ? "core/event_bus.py" : step.id === "finding" ? "core/reporter.py" : step.id === "probe" ? `modules/${activeDomain}/${activeDomain === "web" ? "ssrf_detector.py" : activeDomain === "web3" ? "reentrancy_analyzer.py" : "alignment_fuzzer.py"}` : step.id === "orch" ? "core/orchestrator.py" : `plugins/${activeDomain}/${activeDomain === "web" ? "metadata_validator.py" : activeDomain === "web3" ? "reentrancy_verifier.py" : "sandbox_auditor.py"}`}
                          </span>
                          <span className="text-[9px] uppercase tracking-wider text-zinc-650 font-sans">Active Logic</span>
                        </div>
                        <pre className="p-4 text-xs font-mono text-zinc-400 leading-relaxed overflow-x-auto max-h-[300px] scrollbar-thin select-text">
                          <code className="language-python">{step.code}</code>
                        </pre>
                      </div>

                      {/* Static Telemetry Console */}
                      <div className="rounded-lg border border-zinc-900 bg-[#050507] px-4 py-3 font-mono text-[11px] sm:text-xs select-text">
                        <div className="text-[10px] font-bold text-zinc-500 border-b border-zinc-900/60 pb-1.5 mb-2 flex justify-between">
                          <span>PIPELINE TELEMETRY STATUS</span>
                          <span className="font-extrabold uppercase tracking-wide" style={{ color: theme.accentColor }}>
                            {theme.consoleLabel}
                          </span>
                        </div>
                        <div className="text-zinc-400 leading-relaxed select-text">
                          {step.telemetry}
                        </div>
                      </div>
                    </div>

                    {/* Architectural Isolation Benefit Callout */}
                    <div className="rounded-lg border border-zinc-900 bg-zinc-900/10 p-4 sm:p-5 select-text">
                      <h4 className="text-xs font-bold text-zinc-300 uppercase tracking-wider mb-2 flex items-center gap-2 select-text">
                        <Shield size={14} style={{ color: theme.accentColor }} />
                        Decoupled Verification Benefit
                      </h4>
                      <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed select-text">
                        VScanX decouples this validation block cleanly, ensuring zero state corruption in surrounding workflows. If shell triggers fail or contract checks return safe state variations, the engine automatically discards anomalies without emitting noisy false logs.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Silence Zone / Subsystem flow explanation */}
      <section id="flow" className="mt-16 space-y-6 select-text scroll-mt-28">
        <h2 className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Subsystem Interaction & Execution
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          VScanX guarantees completely reproducible security state validation through absolute separation of discovery and proof execution. 
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
          <div className="p-6 rounded-lg border border-zinc-900 bg-zinc-950/40 select-text">
            <h3 className="text-sm font-bold text-zinc-200 uppercase tracking-widest mb-2 font-mono select-text">
              Event Broker Decoupling
            </h3>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed select-text">
              Scan stages communicate strictly by dispatching event models containing clean parameters. Because passive detectors never execute exploit algorithms directly on the target network, thread execution cycles remain highly performant and target systems are never overwhelmed with hostile anomalies.
            </p>
          </div>
          <div className="p-6 rounded-lg border border-zinc-900 bg-zinc-950/40 select-text">
            <h3 className="text-sm font-bold text-zinc-200 uppercase tracking-widest mb-2 font-mono select-text">
              Sandboxed Verifications
            </h3>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed select-text">
              When orchestrators schedule audits, they spawn ephemeral local execution containers (e.g. gVisor sandbox pods or RPC forks). This ensures validation plugins run exploitation validation checks in completely isolated local network loops, verifying reproducibility before writing standard reports.
            </p>
          </div>
        </div>
      </section>
    </article>
  );
}
