import CodeBlock from "@/components/CodeBlock";

export default function CliReferenceDocs() {
  return (
    <article className="prose prose-invert prose-zinc max-w-none prose-base sm:prose-lg leading-relaxed select-text">
      
      {/* 1. Quick Summary */}
      <header className="mb-10 select-text">
        <h1 id="overview" className="text-3xl font-extrabold tracking-tight text-zinc-50 mb-3 select-text">
          CLI Interface Reference
        </h1>
        <p className="text-zinc-400 text-lg select-text max-w-3xl">
          Search, copy, and configure VScanX command parameters to orchestrate scans, compute deltas, or execute regressions.
        </p>
      </header>

      {/* 2. Core Mental Model */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="mental-model" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Mental Model
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          The VScanX Command Line Interface (CLI) is the central orchestration entrypoint (`vscanx.py`). It is built to run cleanly in both local developer terminals and headless CI/CD containers. 
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Every primary capability—running profiles, executing isolated verifications, loading cached snapshots, and running security state regressions—is mapped to explicit, deterministic command flags.
        </p>
      </section>

      {/* 3. CLI Arguments Matrix */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="options" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          CLI Parameter Matrix
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Use the following scannable table to map framework runtime configurations:
        </p>

        <div className="overflow-x-auto rounded-lg border border-zinc-900 bg-zinc-950/40 my-6">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-zinc-900 bg-zinc-900/20 text-zinc-300 font-bold">
                <th className="p-4">Command Flag</th>
                <th className="p-4">Type</th>
                <th className="p-4">Default</th>
                <th className="p-4">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-900 text-zinc-400">
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">-t, --target</td>
                <td className="p-4 text-zinc-500">String</td>
                <td className="p-4">None</td>
                <td className="p-4">Specifies the scanning target (URL, IP address, or smart contract address).</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">--profile</td>
                <td className="p-4 text-zinc-500">String</td>
                <td className="p-4">web</td>
                <td className="p-4">Selects the scanner module profile domain: <code>web</code>, <code>network</code>, <code>web3</code>, or <code>agentic</code>.</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">--verify</td>
                <td className="p-4 text-zinc-500">Flag</td>
                <td className="p-4">False</td>
                <td className="p-4">Orchestrates dynamic sandbox validation payload execution on flagged anomalies.</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">--replay</td>
                <td className="p-4 text-zinc-500">String</td>
                <td className="p-4">None</td>
                <td className="p-4">Loads and triggers regression tests using a historical serialized run snapshot JSON file path.</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">--diff</td>
                <td className="p-4 text-zinc-500">String String</td>
                <td className="p-4">None</td>
                <td className="p-4">Accepts two run snapshot IDs to compute security posture mutations ($S_A \rightarrow S_B$).</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">--fail-on-critical</td>
                <td className="p-4 text-zinc-500">Flag</td>
                <td className="p-4">False</td>
                <td className="p-4">Causes the CLI engine to exit with status <code>1</code> if verified critical anomalies are returned.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* 4. Practical CLI Recipes */}
      <section className="space-y-6 select-text mb-8">
        <h2 id="recipes" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Practical Command Recipes
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Use the following copy-paste friendly configurations for standard operational scenarios:
        </p>

        <div className="space-y-6 select-text">
          <div>
            <h4 className="text-sm font-bold text-zinc-200 mb-2">Orchestrate Web Anomalies & Spawner Sandboxes</h4>
            <p className="text-xs text-zinc-500 mb-3 leading-normal">
              Performs active redirect and SQLi passive scans, emitting events to spawn isolated validation containers:
            </p>
            <CodeBlock code="python vscanx.py --target enterprise-api.com --profile web --verify" />
          </div>

          <div>
            <h4 className="text-sm font-bold text-zinc-200 mb-2">Verify Web3 Reentrancy on Ethereum Forks</h4>
            <p className="text-xs text-zinc-500 mb-3 leading-normal">
              Pulls bytecode structure and simulates withdrawal loops inside an isolated local Ethereum RPC fork:
            </p>
            <CodeBlock code="python vscanx.py --target 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe --profile web3 --verify" />
          </div>

          <div>
            <h4 className="text-sm font-bold text-zinc-200 mb-2">Calculate Posture Deltas between Runs</h4>
            <p className="text-xs text-zinc-500 mb-3 leading-normal">
              Compares two historical snapshots to isolate introduced regressions or resolved vulnerabilities:
            </p>
            <CodeBlock code="python vscanx.py --diff run_291A_web.json run_291B_web.json" />
          </div>
        </div>
      </section>

    </article>
  );
}
