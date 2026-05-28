import CodeBlock from "@/components/CodeBlock";

export default function GettingStartedDocs() {
  return (
    <article className="prose prose-invert prose-zinc max-w-none prose-base sm:prose-lg leading-relaxed select-text">
      
      {/* 1. Quick Summary */}
      <header className="mb-10 select-text">
        <h1 id="overview" className="text-3xl font-extrabold tracking-tight text-zinc-50 mb-3 select-text">
          Getting Started
        </h1>
        <p className="text-zinc-400 text-lg select-text max-w-3xl">
          Initialize your environment and execute your first verification-driven security analysis scan in under five minutes.
        </p>
      </header>

      {/* 2. Core Mental Model */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="mental-model" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Mental Model
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          VScanX is engineered under a **verification-first** philosophy. Unlike traditional scanners that output hundreds of speculative warnings based on basic version headers or regex matches, VScanX models your system's dynamic posture and automatically deploys safe, isolated payloads to prove whether a vulnerability is actually reproducible.
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Running a scan involves three simple phases:
        </p>
        <ol className="list-decimal pl-6 text-zinc-400 text-base space-y-2 select-text">
          <li><strong>Probing:</strong> A lightweight module analyzes target surface interfaces (HTTP parameters, EVM contract addresses, RPC nodes, or LLM agent endpoints).</li>
          <li><strong>Eventing:</strong> Detected anomalies are emitted as typed event contracts to a central event bus.</li>
          <li><strong>Validation:</strong> The orchestrator spawns an isolated sandbox to run dynamic verification payloads, confirming the finding with absolute confidence.</li>
        </ol>
      </section>

      {/* 3. System Requirements & Prerequisites */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="requirements" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Prerequisites & Requirements
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Ensure your host system meets the following engineering baselines before installing:
        </p>
        <ul className="list-disc pl-6 text-zinc-400 text-base space-y-2 select-text">
          <li><strong>Runtime:</strong> Python 3.11 or higher.</li>
          <li><strong>Network Libs:</strong> Raw socket capture capabilities (requires standard administrative permissions or root access to mount Scapy engines).</li>
          <li><strong>Containerization:</strong> Docker or gVisor socket accessibility (strictly required if orchestrating containerized sandbox validation checks).</li>
        </ul>

        {/* Warning Callout Box */}
        <div className="rounded-lg border border-red-950 bg-red-950/10 p-5 mt-4 select-text">
          <h4 className="text-sm font-bold text-red-400 uppercase tracking-wider mb-2 select-text">
            [!] Administrative / Root Permissions
          </h4>
          <p className="text-xs sm:text-sm text-red-500/80 leading-relaxed select-text">
            Because VScanX's network modules utilize standard Scapy interfaces to perform packet injection and passive TLS handshakes, raw socket privileges are required. Run the orchestrator with sudo privileges on Linux, or ensure administrative command terminals are active on Windows.
          </p>
        </div>
      </section>

      {/* 4. Practical Setup & Installation */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="installation" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Installation Walkthrough
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Clone the core framework source repository and prepare your Python virtual environment:
        </p>
        
        <CodeBlock code="git clone https://github.com/hnikhil-dev/VScanX.git
cd VScanX" />

        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Create and activate an isolated virtual environment to prevent package namespace collisions:
        </p>

        <CodeBlock code="# On Unix / macOS
python -m venv venv
source venv/bin/activate

# On Windows
python -m venv venv
venv\Scripts\activate" />

        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Install all core framework dependencies via the requirements index:
        </p>

        <CodeBlock code="pip install -r requirements.txt" />
      </section>

      {/* 5. Running Your First Scan */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="first-scan" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Executing Your First Scan
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          VScanX supports specialized scanning domains out of the box. Execute a verified Web scan using the CLI entrypoint:
        </p>

        <CodeBlock code="python vscanx.py -t target-url.com --verify" />

        {/* Tip Callout Box */}
        <div className="rounded-lg border border-zinc-900 bg-zinc-900/40 p-5 mt-4 select-text">
          <h4 className="text-xs font-bold text-zinc-300 uppercase tracking-wider mb-2 select-text">
            💡 Pro-Tip: Decoupled Replay Cache
          </h4>
          <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed select-text">
            Every scan cycle automatically saves a serialized run snapshot under <code>~/.vscanx/runs/</code>. You can perform rapid delta regression tests on target code mutations later without running a full re-scan by calling: <code>python vscanx.py --replay &lt;run_id&gt;</code>.
          </p>
        </div>
      </section>

      {/* 6. Standard Scan Profiles Matrix */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="profiles" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Core Scanning Profiles
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          VScanX organizes modules into four primary scan profiles:
        </p>

        <div className="overflow-x-auto rounded-lg border border-zinc-900 bg-zinc-950/40 my-6">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-zinc-900 bg-zinc-900/20 text-zinc-300 font-bold">
                <th className="p-4">Profile Flag</th>
                <th className="p-4">Target Schema</th>
                <th className="p-4">Verification Sandbox</th>
                <th className="p-4">Sample Command</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-900 text-zinc-400">
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">--profile web</td>
                <td className="p-4">HTTP APIs & Web Apps</td>
                <td className="p-4">Isolated Docker container</td>
                <td className="p-4 font-mono text-xs">python vscanx.py -t target.io --profile web --verify</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">--profile network</td>
                <td className="p-4">Ports & TLS Layers</td>
                <td className="p-4">Raw socket assertion checks</td>
                <td className="p-4 font-mono text-xs">python vscanx.py -t 192.168.1.1 --profile network --verify</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">--profile web3</td>
                <td className="p-4">Ethereum Contracts</td>
                <td className="p-4">Local Anvil RPC fork node</td>
                <td className="p-4 font-mono text-xs">python vscanx.py -t 0xde0B... --profile web3 --verify</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">--profile agentic</td>
                <td className="p-4">AI Agent Prompt APIs</td>
                <td className="p-4">gVisor runtime shell pod</td>
                <td className="p-4 font-mono text-xs">python vscanx.py -t api.agent.io --profile agentic --verify</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* 7. Troubleshooting Common Onboarding Failures */}
      <section className="space-y-6 select-text mb-8">
        <h2 id="troubleshooting" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Onboarding Troubleshooting
        </h2>
        
        <div className="space-y-4 select-text">
          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-2">Issue: Scapy Raw Socket Bind Error</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              <strong>Resolution:</strong> On Linux, prepending <code>sudo</code> is required to bind socket listeners. On Windows, make sure the Npcap/WinPcap driver is active. Alternatively, specify a safe passive network interface manually: <code>python vscanx.py -t target.io --interface eth0</code>.
            </p>
          </div>

          <div className="border border-zinc-900 rounded-lg p-5">
            <h4 className="text-sm font-bold text-zinc-200 mb-2">Issue: Docker Socket Validation Timeout</h4>
            <p className="text-xs sm:text-sm text-zinc-500 leading-relaxed">
              <strong>Resolution:</strong> Ensure the Docker daemon is active and your current shell user is added to the <code>docker</code> security group. If running in a local CI sandbox without container access, use the passive mode fallback flags: <code>--verify-mode local-only</code>.
            </p>
          </div>
        </div>
      </section>

    </article>
  );
}
