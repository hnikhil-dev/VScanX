import CodeBlock from "@/components/CodeBlock";

export default function ReplayDiffDocs() {
  return (
    <article className="prose prose-invert prose-zinc max-w-none prose-base sm:prose-lg leading-relaxed select-text">
      
      {/* 1. Quick Summary */}
      <header className="mb-10 select-text">
        <h1 id="overview" className="text-3xl font-extrabold tracking-tight text-zinc-50 mb-3 select-text">
          Replay & Diff System
        </h1>
        <p className="text-zinc-400 text-lg select-text max-w-3xl">
          Leverage continuous security state regression testing, run snapshot diffing, and automated vulnerability replays inside your developer pipeline.
        </p>
      </header>

      {/* 2. Core Mental Model */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="mental-model" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Mental Model
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          A fundamental weakness of security scanning is the lack of historical continuity. Traditional tools scan targets as if they were fresh, blank slates, failing to recognize regressions, mutations, or resolved posture states.
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          VScanX solves this by introducing a **Replay & Diff System**. Every scan output is indexed as a serialized state snapshot to disk (saved inside <code>~/.vscanx/runs/</code>). Developers can perform rapid state regression tracking:
        </p>
        <ul className="list-disc pl-6 text-zinc-400 text-base space-y-2 select-text">
          <li><strong>Replay Engine:</strong> Triggers the exact validation payload cached in a historical run, checking if a patched vulnerability has been re-introduced.</li>
          <li><strong>Diff Engine:</strong> Compares two run state snapshots ($S_A \rightarrow S_B$) to isolate precisely what security elements mutated, resolving target anomalies and highlighting fresh exposures.</li>
        </ul>
      </section>

      {/* 3. Run State Serialization & Storage */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="serialization" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Snapshot Storage & Run Indexing
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          When VScanX completes an audit cycle, it serializes its findings and network metadata schema into a dynamic run file. Run snapshots are saved inside a hidden local system index:
        </p>
        
        <CodeBlock code="# State storage directory structure
~/.vscanx/runs/
├── run_291A_web.json
├── run_404C_network.json
└── run_701D_web3.json" />

        <p className="text-base text-zinc-400 leading-relaxed select-text">
          These run snapshots store the exact URL, verification inputs, parameters, and expected response payloads, allowing the replay engine to validate reproducibility instantly.
        </p>
      </section>

      {/* 4. Delta Comparison Engine */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="delta-diff" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          The State Diff Engine
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          The delta comparison algorithm resides inside <code>core/state/diff.py</code>. By calling the CLI with the <code>--diff</code> flag, developers can calculate comparative mutations between scan cycles:
        </p>
        
        <CodeBlock code="python vscanx.py --diff run_291A run_291B" />

        <p className="text-base text-zinc-400 leading-relaxed select-text">
          The following is a realistic JSON diff snapshot output, documenting a security posture transition where a weak SSL cipher suite was successfully resolved, but a critical open redirect regression was introduced:
        </p>

        <CodeBlock code={`{
  "run_source": "run_291A",
  "run_comparison": "run_291B",
  "deltas": [
    {
      "module": "modules.network.crypto_tls",
      "type": "WEAK_CIPHER_ALLOWED",
      "mutation": "RESOLVED",
      "evidence": "3DES/RC4 cipher suites disabled successfully."
    },
    {
      "module": "modules.web.open_redirect",
      "type": "REDIRECT_BYPASS_VERIFIED",
      "mutation": "INTRODUCED",
      "evidence": "Parameter 'next' accepts dynamic http://malicious-redirect.io redirection payload."
    }
  ]
}`} />
      </section>

      {/* 5. Continuous Integration (CI/CD) Workflow */}
      <section className="space-y-6 select-text mb-8">
        <h2 id="cicd-pipelines" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Continuous Integration Pipeline Integration
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Because VScanX is engineered for engineering pipelines, you can run automated vulnerability regressions inside your GitHub Actions workflows. 
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          The following GitHub Actions YAML demonstrates running a regression test using historical snapshots, failing the pipeline immediately if a critical reproducible finding is reintroduced:
        </p>

        <CodeBlock code="name: Continuous Security Regression

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v3

      - name: Setup Python environment
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt

      - name: Execute Security State Replays
        run: |
          # Replay historical verified run snapshot
          python vscanx.py --replay run_291A_web.json --fail-on-critical" />
      </section>

    </article>
  );
}
