import CodeBlock from "@/components/CodeBlock";

export default function ModulesDocs() {
  return (
    <article className="prose prose-invert prose-zinc max-w-none prose-base sm:prose-lg leading-relaxed select-text">
      
      {/* 1. Quick Summary */}
      <header className="mb-10 select-text">
        <h1 id="overview" className="text-3xl font-extrabold tracking-tight text-zinc-50 mb-3 select-text">
          Scanner Modules Reference
        </h1>
        <p className="text-zinc-400 text-lg select-text max-w-3xl">
          Explore the catalog of VScanX's core detection modules and learn their operational workflows, detection rules, and validation limits.
        </p>
      </header>

      {/* 2. Core Mental Model */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="mental-model" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Mental Model
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          VScanX divides scanning capabilities into three specialized target domains: **Web**, **Web3 (Smart Contracts)**, and **Agentic AI**.
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Instead of running high-impact active scans directly on live assets, VScanX modules use light passive probing to identify anomaly signatures first. If an anomaly threshold is reached, they publish typed contracts to the central event broker, delegating exploit validations cleanly to sandboxed plugins.
        </p>
      </section>

      {/* 3. Web Modules */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="web-modules" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Web Application Modules
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Designed to identify and verify traditional API vulnerabilities:
        </p>

        <div className="space-y-4 select-text">
          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-1">idor_detector.py</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              <strong>Purpose:</strong> Scans REST API endpoints for Insecure Direct Object Reference vulnerabilities. <br />
              <strong>Workflow:</strong> Passive scanner records user identification parameters in query strings or JSON bodies. The validator container tests parameter permutations across different authenticated session tokens to verify access bypasses.
            </p>
          </div>

          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-1">sqli_detector.py</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              <strong>Purpose:</strong> Audits query input paths for SQL Injection vulnerabilities. <br />
              <strong>Workflow:</strong> Probes parameters with safe boolean boundary tests. If anomaly behavior (such as SQL syntax error headers or response time fluctuations) is flagged, the event spawns a local database clone to verify execution breakout safely.
            </p>
          </div>
        </div>
      </section>

      {/* 4. Web3 Modules */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="web3-modules" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Web3 & Smart Contract Modules
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Audits compiled smart contract bytecodes and live chain transactions:
        </p>

        <div className="space-y-4 select-text">
          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-1">reentrancy_analyzer.py</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              <strong>Purpose:</strong> Detects missing state mutations before recursive withdrawal calls in Solidity bytecode. <br />
              <strong>Workflow:</strong> Pulls AST structure via RPC node interfaces. When a vulnerability signature matches, VScanX forks the blockchain locally inside an Anvil RPC sandbox and deploys simulated recursive withdrawal calls to assert if balance depletion can succeed.
            </p>
          </div>

          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-1">access_control_checker.py</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              <strong>Purpose:</strong> Audits privileged contract function modifiers (such as <code>onlyOwner</code>). <br />
              <strong>Workflow:</strong> Analyzes ABI function definitions. If key withdrawal or management functions lack access controls, validation checks execute simulated ownership bypass transactions on local state forks.
            </p>
          </div>
        </div>
      </section>

      {/* 5. Agentic AI Modules */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="ai-modules" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Agentic AI Modules
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Designed for validating LLM prompt boundaries and sandbox escape anomalies:
        </p>

        <div className="space-y-4 select-text">
          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-1">prompt_injection_fuzzer.py</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              <strong>Purpose:</strong> Jailbreaks system prompt variables using boundary query bypass scripts. <br />
              <strong>Workflow:</strong> Queries target LLM endpoints. If model alignment fails and the prompt fuzzer extracts restricted instructions, VScanX schedules isolated sandbox breakout tests.
            </p>
          </div>

          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-1">code_execution_prober.py</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              <strong>Purpose:</strong> Audits dynamic code interpreter and execution sandboxes for host RCE. <br />
              <strong>Workflow:</strong> Spawns execution probes. Validates container breakouts inside highly secure gVisor (runsc) pods by testing shell escape commands deterministically.
            </p>
          </div>
        </div>
      </section>

      {/* 6. Explicit Operational Limitations */}
      <section className="space-y-6 select-text mb-8">
        <h2 id="limitations" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Unbiased Operational Limitations
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          To maintain engineering trust, VScanX documents explicit boundary limitations and uncertainty constraints honestly:
        </p>
        
        <div className="space-y-4 select-text">
          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-2">Web3 Fork Latencies</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              Smart contract fork-state validations rely heavily on RPC response speeds. Under high network latencies or rate-limited RPC node connections, validation simulations can experience timeouts, leading to unverified classification fallbacks.
            </p>
          </div>

          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-2">AI Fuzzer Heuristic Boundaries</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              AI prompt alignment fuzzing relies on dynamic semantic classifiers to identify jailbreaks. Because LLM outputs are naturally non-deterministic, highly unique bypass vectors may occasionally fall outside heuristic detection models.
            </p>
          </div>
        </div>
      </section>

    </article>
  );
}
