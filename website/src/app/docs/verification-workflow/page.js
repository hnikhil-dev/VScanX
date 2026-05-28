import CodeBlock from "@/components/CodeBlock";

export default function VerificationWorkflowDocs() {
  return (
    <article className="prose prose-invert prose-zinc max-w-none prose-base sm:prose-lg leading-relaxed select-text">
      
      {/* 1. Quick Summary */}
      <header className="mb-10 select-text">
        <h1 id="overview" className="text-3xl font-extrabold tracking-tight text-zinc-50 mb-3 select-text">
          Verification Workflow
        </h1>
        <p className="text-zinc-400 text-lg select-text max-w-3xl">
          Trace VScanX's end-to-end execution pipeline from lightweight fuzzing to sandboxed exploit validation and normalized report generation.
        </p>
      </header>

      {/* 2. Core Mental Model */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="mental-model" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Mental Model
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          To achieve reproducibility-driven security tracking and reduce false positives, VScanX separates targets discovery from active exploit execution. If a scanning module discovers a potential redirect vulnerability on your target API, it never directly executes the validation attack on the main target host.
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Instead, the framework coordinates an isolated validation sequence—spinning up sandboxed nodes, local EVM state forks, or gVisor workspaces to safely assert exploitability before compiling JSON findings.
        </p>
      </section>

      {/* 3. The 5 Scanning Stages */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="lifecycle" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          The 5 Chronological Stages
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Every scan lifecycle progresses through five distinct execution boundaries:
        </p>

        <div className="space-y-6 select-text my-6">
          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 font-mono mb-2 uppercase">Stage 1: Passive Probing & Discovery</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              Lightweight modules (e.g. <code>idor_detector.py</code> or <code>reentrancy_analyzer.py</code>) scan baseline targets. They analyze query parameters, headers, transaction histories, or smart contract AST bytecode structures. No active exploit payloads are sent.
            </p>
          </div>

          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 font-mono mb-2 uppercase">Stage 2: Event Broadcast (Typed Event Contracts)</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              If an anomaly is flagged, the module publishes a strongly-typed <code>AnomalyEvent</code> containing target metadata to the Event Bus (<code>core/events/bus.py</code>). The scanner module cleanly exits, freeing up thread pools.
            </p>
          </div>

          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 font-mono mb-2 uppercase">Stage 3: Sandbox Provisioning & Orchestration</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              The central Orchestrator consumes the event. It automatically provisions an ephemeral, fully isolated sandbox environment tailored to the module domain (spawning a local Docker container or executing a local block-state EVM fork).
            </p>
          </div>

          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 font-mono mb-2 uppercase">Stage 4: Exploit Payload Validation</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              The Verification Engine (<code>core/verify/engine.py</code>) triggers dynamic exploit checks inside the sandbox. It measures outcomes deterministically (e.g. verifying root command execution or contract balance mutation), proving exploitability safely.
            </p>
          </div>

          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 font-mono mb-2 uppercase">Stage 5: Canonical Report Generation</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              Only verified findings are compiled to reports. The findings JSON lists exact validation traces and proof schemas, guaranteeing immediate, low-noise reproducibility records for developers.
            </p>
          </div>
        </div>
      </section>

      {/* 4. Event Schema Payload Example */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="event-contracts" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Decoupled Event Contract Payload
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          VScanX defines strongly-typed schema models for event serialization (`core/events/schemas.py`). The following is a realistic `AnomalyEvent` payload contract:
        </p>

        <CodeBlock code={`{
  "event_id": "ev_981A402D",
  "timestamp": "2026-05-27T14:02:11Z",
  "type": "SSRF_ANOMALY_FOUND",
  "payload": {
    "target_url": "https://enterprise-target.io/login",
    "vulnerable_parameter": "next",
    "passive_heuristic": "redirect_query_detect"
  },
  "trace_id": "tr_00912BCX"
}`} />
      </section>

      {/* 5. Production-like Verification Trace Logs */}
      <section className="space-y-6 select-text mb-8">
        <h2 id="verification-traces" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Realistic Verification Traces
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          When the Verification Engine audits a flagged event inside an EVM or Web sandbox, it writes structured telemetry traces. The following log snippet illustrates a successful, high-confidence metadata verification:
        </p>

        <CodeBlock code="[22:02:15] [core.orchestrator] Received event: SSRF_ANOMALY_FOUND (trace_id: tr_00912BCX)
[22:02:16] [core.orchestrator] Spawning isolated Docker validation container: vscanx/val-web:latest
[22:02:16] [core.verify.engine] Executing active metadata payload assertions inside sandbox...
[22:02:17] [core.verify.engine] payload dispatched: https://enterprise-target.io/login?next=http://169.254.169.254/latest/meta-data/
[22:02:18] [core.verify.engine] AWS metadata response captured: ami-id / iam/security-credentials
[22:02:18] [core.verify.engine] [SUCCESS] Target vulnerable to Critical SSRF. Confidence: 1.0 (VERIFIED)
[22:02:19] [core.reporter] Compiling canonical finding for trace: tr_00912BCX" />
      </section>

    </article>
  );
}
