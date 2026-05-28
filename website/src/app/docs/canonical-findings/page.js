import CodeBlock from "@/components/CodeBlock";

export default function CanonicalFindingsDocs() {
  return (
    <article className="prose prose-invert prose-zinc max-w-none prose-base sm:prose-lg leading-relaxed select-text">
      
      {/* 1. Quick Summary */}
      <header className="mb-10 select-text">
        <h1 id="overview" className="text-3xl font-extrabold tracking-tight text-zinc-50 mb-3 select-text">
          Canonical Findings Schema
        </h1>
        <p className="text-zinc-400 text-lg select-text max-w-3xl">
          Integrate and consume VScanX's standardized, strongly-typed JSON data contract designed for operational reliability.
        </p>
      </header>

      {/* 2. Core Mental Model */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="mental-model" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Mental Model
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          A common frustration with security tooling is inconsistent output structures. Many scanners write text reports, customized HTML summaries, or noisy XML grids that developers must write heavy, custom parsers to consume inside pipelines.
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          VScanX completely eliminates this variance by requiring **every single finding** to adhere strictly to a rigid, standardized, and strongly-typed data schema (defined inside <code>core/schemas.py</code>). 
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Whether a vulnerability originates from an EVM smart contract sweep, a cloud SSRF validation, or a prompt injection jailbreak, the JSON payload follows the exact same logical structure.
        </p>
      </section>

      {/* 3. The Complete Schema Contract JSON */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="schema" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          The JSON Findings Schema Contract
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          The following is a realistic output artifact produced by the Verification Engine upon successfully confirming a critical SSRF vulnerability:
        </p>

        <CodeBlock code={`{
  "finding_id": "CAN-2026-F981",
  "trace_id": "tr_00912BCX",
  "signature": "Open Redirect Vulnerability",
  "module": "modules.web.open_redirect_prober",
  "severity": "CRITICAL",
  "confidence": 1.0,
  "verification": {
    "status": "VERIFIED",
    "verified_at": "2026-05-27T14:02:18Z",
    "proof": {
      "request_method": "GET",
      "exploit_payload": "/admin?next=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
      "response_evidence": {
        "status_code": 200,
        "header_key": "Server",
        "content_match": "ami-id"
      }
    }
  },
  "reproducibility_metadata": {
    "reproduction_mode": "docker_sandbox",
    "sandbox_image": "vscanx/val-web:latest",
    "replay_linkage_id": "run_291A_web"
  }
}`} />
      </section>

      {/* 4. Field-by-Field Reference Matrix */}
      <section className="space-y-6 select-text mb-12">
        <h2 id="fields" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Schema Field Reference
        </h2>
        
        <div className="overflow-x-auto rounded-lg border border-zinc-900 bg-zinc-950/40 my-6">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-zinc-900 bg-zinc-900/20 text-zinc-300 font-bold">
                <th className="p-4">JSON Key</th>
                <th className="p-4">Type</th>
                <th className="p-4">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-900 text-zinc-400">
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">finding_id</td>
                <td className="p-4 text-zinc-500">String</td>
                <td className="p-4">Standardized canonical identifier unique to the vulnerability class.</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">severity</td>
                <td className="p-4 text-zinc-500">Enum</td>
                <td className="p-4">Vulnerability severity classification: <code>LOW</code>, <code>MEDIUM</code>, <code>HIGH</code>, or <code>CRITICAL</code>.</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">confidence</td>
                <td className="p-4 text-zinc-500">Float</td>
                <td className="p-4">Confidence scoring metric mapping verification precision, varying from 0.0 to 1.0 (VERIFIED).</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200 font-sans">verification.status</td>
                <td className="p-4 text-zinc-500">Enum</td>
                <td className="p-4">Confirmation level: <code>UNVERIFIED</code>, <code>PENDING</code>, or <code>VERIFIED</code>.</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200 font-sans">verification.proof</td>
                <td className="p-4 text-zinc-500">Object</td>
                <td className="p-4">Dynamic details capturing the exact request, exploit payload, and response content match evidence.</td>
              </tr>
              <tr>
                <td className="p-4 font-mono font-bold text-zinc-200">reproducibility_metadata</td>
                <td className="p-4 text-zinc-500">Object</td>
                <td className="p-4">Orchestration specs storing sandbox image requirements and the replay snapshot linkage id.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* 5. Custom CI/CD Build failure script integration */}
      <section className="space-y-6 select-text mb-8">
        <h2 id="pipeline-integration" className="text-xl font-bold text-zinc-100 border-b border-zinc-900 pb-2 select-text">
          Automated CI/CD Build Failures
        </h2>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          Because VScanX findings are perfectly structured and reproducible, you can parse the JSON output cleanly to fail integration builds.
        </p>
        <p className="text-base text-zinc-400 leading-relaxed select-text">
          The following Python script illustrates how a deployment pipeline parses a VScanX report and exits with status <code>1</code> only if a highly reproducible, critical vulnerability is actively verified:
        </p>

        <CodeBlock code={`# scripts/pipeline_gate.py
import sys
import json

def parse_report(report_path):
    try:
        with open(report_path, 'r') as file:
            data = json.load(file)
            
        findings = data.get('findings', [])
        for item in findings:
            severity = item.get('severity')
            status = item.get('verification', {}).get('status')
            confidence = item.get('confidence', 0.0)
            
            # Block deploy only if vulnerability is critical and fully verified
            if severity == 'CRITICAL' and status == 'VERIFIED' and confidence == 1.0:
                print(f'[CI/CD GATE] Critical Reproducible Anomaly Flagged: {item["signature"]}')
                sys.exit(1)
                
        print('[CI/CD GATE] Zero verified critical regressions found. Approval granted.')
        sys.exit(0)
    except Exception as err:
        print(f'[CI/CD GATE] Error parsing VScanX report: {err}')
        sys.exit(1)

if __name__ == '__main__':
    parse_report(sys.argv[1])`} />
      </section>

    </article>
  );
}
