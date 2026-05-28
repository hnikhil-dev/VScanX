import CodeBlock from "@/components/CodeBlock";

export default function CoreConceptsDocs() {
  return (
    <article className="prose prose-invert prose-zinc max-w-none prose-base sm:prose-lg leading-relaxed select-text">
      
      {/* 1. Quick Summary */}
      <header className="mb-10 select-text">
        <h1 id="overview" className="text-3xl font-extrabold tracking-tight text-zinc-50 mb-3 select-text">
          Core Concepts
        </h1>
        <p className="text-zinc-400 text-lg select-text max-w-3xl">
          Understand the structural design patterns and core engineering principles that drive VScanX's reproducibility-oriented security verification engine.
        </p>
      </header>

      {/* 2. Framework Design Principles */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="principles" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Framework Design Principles
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          VScanX is built from the ground up on five architectural pillars to provide a robust, low-noise developer framework:
        </p>
        
        <div className="space-y-4 my-6 select-text">
          <div className="p-5 rounded-lg border border-zinc-900 bg-zinc-950/20">
            <h4 className="text-sm font-bold text-zinc-200 font-mono mb-2 uppercase">1. Verification over Speculation</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              We never report an alert based solely on passive signatures or basic version banners. A security issue is treated as a verified finding only if VScanX can actively reproduce the vulnerability state dynamically inside a clean sandbox.
            </p>
          </div>
          <div className="p-5 rounded-lg border border-zinc-900 bg-zinc-950/20">
            <h4 className="text-sm font-bold text-zinc-200 font-mono mb-2 uppercase">2. Replay over Ephemeral Scans</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              Traditional scanning cycles are ephemeral, leaving no regression trace. VScanX serializes all scan states to disk. Historical runs are completely replayable in isolation, enabling reliable debugging of vulnerabilities across commits.
            </p>
          </div>
          <div className="p-5 rounded-lg border border-zinc-900 bg-zinc-950/20">
            <h4 className="text-sm font-bold text-zinc-200 font-mono mb-2 uppercase">3. Structured Findings over Raw Output</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              Raw console dumps and arbitrary textual alerts are replaced by strongly-typed, JSON-contract findings. Every single finding adheres strictly to a rigid schema, making it directly consumable by automated CI/CD tooling.
            </p>
          </div>
          <div className="p-5 rounded-lg border border-zinc-900 bg-zinc-950/20">
            <h4 className="text-sm font-bold text-zinc-200 font-mono mb-2 uppercase">4. Low-Noise Workflows over Scan Volume</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              Instead of running thousands of shallow signature checks that generate bloated reports, VScanX runs highly targeted, confidence-scored verification routines. We prioritize engineering trust and actionable evidence over sheer alert volume.
            </p>
          </div>
          <div className="p-5 rounded-lg border border-zinc-900 bg-zinc-950/20">
            <h4 className="text-sm font-bold text-zinc-200 font-mono mb-2 uppercase">5. Deterministic Pipelines over Opaque Heuristics</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              Detection components and exploit validation tools communicate exclusively by publishing structured event payloads to decoupled broadcast event buses, establishing a highly predictable and clean runtime execution pipeline.
            </p>
          </div>
        </div>
      </section>

      {/* 3. Core Mental Model: Evolving Security States */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="state-evolution" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Systems as Evolving Security States
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          At the intellectual center of VScanX is a fundamental paradigm shift: **we treat targets not as static hosts, but as dynamic, evolving state machines.**
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          A traditional scanner issues HTTP requests, looks for matching regex strings, and writes a static alert. If the developer deploys a patch, the scanner has no historical context to compare the changes against, relying instead on a complete scan run.
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          VScanX models a target's posture as a security state snapshot S(t). Every scan run creates a serialized snapshot containing verified vulnerability signatures and specific verification payloads. During subsequent scans S(t+1), the engine calculates **state mutations (S(t) ➔ S(t+1))**:
        </p>
        
        <ul className="list-disc pl-6 text-zinc-400 text-base space-y-2 select-text">
          <li><strong>Delta Posture isolation:</strong> Immediately flags if an anomaly is resolved or if new attack vectors are introduced.</li>
          <li><strong>Continuous Regression Verification:</strong> Automatically pulls the exact validation payload cached in S(t) to confirm whether a previously closed vulnerability has been re-introduced.</li>
        </ul>
      </section>

      {/* 4. Asynchronous Event Bus Decoupling */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="decoupled-bus" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Decoupled Event Orchestration
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          To maintain speed and safety, VScanX decouples passive fuzzer discovery from heavy container validation using an asynchronous event-driven model (`core/events/bus.py`).
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Scanner modules do not communicate directly. When a module flags a suspicious parameter:
        </p>
        <ol className="list-decimal pl-6 text-zinc-400 text-base space-y-2 select-text">
          <li>It publishes a strongly-typed `AnomalyEvent` contract (e.g. `SSRF_ANOMALY_FOUND` or `REENTRANCY_DETECTED`) to the event bus.</li>
          <li>The central `Orchestrator` receives the event and dynamically maps appropriate verification sandbox requirements.</li>
          <li>The validation engine spawns an isolated sandbox to run verification tests asynchronously.</li>
        </ol>
      </section>

      {/* 5. Sandboxed Verification Boundaries */}
      <section className="space-y-6 select-text mb-8">
        <h2 id="low-noise" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Sandboxed Exploit Verification
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Dynamic validation payloads are highly intrusive. Firing active injection strings directly at targets can corrupt live database tables or trigger denial-of-service alerts. 
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          To validate issues safely, VScanX establishes **isolated sandbox boundaries**:
        </p>
        
        <div className="my-6 border border-zinc-900 rounded-lg bg-zinc-950/20 p-5 select-text">
          <h4 className="text-sm font-bold text-zinc-200 mb-2">Sandbox Containment Mechanisms</h4>
          <ul className="list-disc pl-6 text-xs sm:text-sm text-zinc-500 space-y-2">
            <li><strong>Web/API Sandboxes:</strong> Dynamic Docker containers spawned in isolated target networks.</li>
            <li><strong>Web3 EVM Sandboxes:</strong> Local Ethereum RPC node forks (Anvil) spawned at the specific anomaly block number. Transaction balance mutations are tested fully in isolation without gas costs or target state pollution.</li>
            <li><strong>Agentic AI Sandboxes:</strong> Secure gVisor (runsc) isolated containers created to safely capture and audit prompt escape shell execution attempts.</li>
          </ul>
        </div>
      </section>

    </article>
  );
}
