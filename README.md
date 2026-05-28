# VScanX

VScanX is an open-source, event-driven security scanner that focuses on verified vulnerabilities and low-noise workflows. Instead of relying purely on passive signature matching that flags hundreds of false positives, VScanX verifies findings by automatically generating safe, reproducible proof-of-concept exploits.

It supports multi-layered scanning across web applications, Web3 smart contracts, network ports, and LLM-based AI applications.

## Key Features

* **Verified Findings:** Vulnerabilities are validated with reproduction contracts that log the exact HTTP sequence to prove exploitability.
* **Scan Diffing:** Compare two historical scans to easily track new, resolved, or modified issues across deployments.
* **Verify-Only Replay:** Re-run only the lightweight verifier checks against live targets using saved exploits without performing a full scan.
* **Unified Scope:** Integrated modules for Web App vulnerabilities (SQLi, XSS, IDOR, HPP), Smart Contracts (Reentrancy, Access Control), and Agentic AI (Prompt Injection, Sandbox Escape).
* **Local Docs Platform:** A local-first Next.js documentation dashboard to privately inspect and manage security scan results.

## Quick Start

### Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/hnikhil-dev/VScanX.git
cd VScanX
pip install -r requirements.txt
```

Verify it is installed correctly by showing the options:

```bash
python vscanx.py --help
```

### Running a Scan

Run a basic web scan against a target, assign a scan ID to save state, and export the report:

```bash
python vscanx.py -t "http://127.0.0.1:8080/search?q=test" -s web --scan-id run_001 --format html,json --skip-warning
```

## Common Workflows

### 1. Verify Patches (Verify-Only Replay)
To verify if past vulnerabilities are patched without running a full re-scan, run:

```bash
python vscanx.py --replay-verify --scan-id run_001 --state-dir .vscanx_state -o verify_report_001 --format html
```

### 2. Compare Scans (Diffing)
Compare the security state between two separate runs to see what changed:

```bash
python vscanx.py --diff --scan-id run_001 --scan-id2 run_002 --state-dir .vscanx_state -o diff_report
```

### 3. Re-generate Reports (Replay)
Re-render reports from saved results without hitting the network:

```bash
python vscanx.py --replay --scan-id run_001 --state-dir .vscanx_state --format html,json
```

## Useful CLI Flags

### Scanner Scope
* `-t, --target` : Target URL, IP, or hostname (e.g. `http://127.0.0.1:8080`)
* `-s, --scan-type` : Scan category (`web`, `network`, `mixed`, `web3`, `agentic`). Defaults to `mixed`.
* `--ports` : Custom TCP port range for network sweeps (e.g. `80,443` or `1-1024`)
* `--profile` : Scan profile config (`quick`, `normal`, `full`, `stealth`)
* `--only` : Run specific modules exclusively (e.g. `xss,sqli,headers`)
* `--delay` : Custom delay between requests in seconds (e.g. `0.05` or `1.0`)

### State Management
* `--scan-id` : Identifier used to save scan state, crawl cache, and diff findings
* `--scan-id2` : Secondary scan ID used to compare against `--scan-id` during diffs
* `--state-dir` : Custom folder for saving scan state (defaults to `.vscanx_state`)
* `--resume` : Reuse crawler URL inventory from the matching `--scan-id` to save time

### Authentication
* `--login-url` : Path to login page for session-based testing
* `--username` / `--password` : Basic credentials for login forms
* `--bearer-token` / `--api-key` : Authentication token strings to inject in header requests

### Advanced Options
* `--elite` : Enable vulnerability chaining and safe exploit payload generation
* `--defensive-variants` : Test URL normalization inconsistencies
* `--parallel-modules` : Run web checks concurrently
* `--strict-events` : Fail fast on internal event schema errors (ideal for CI)

## Project Structure

```
├── .vscanx_state/           # Saved scan results and crawler cache
├── reports/                 # Generated exports (.html, .json, .csv, .txt)
├── core/                    # Core orchestration engine and event bus
├── modules/                 # Web, Web3, Network, and AI scanning checks
└── website/                 # Prerendered Next.js documentation dashboard
```

## Development and Testing

Run the test suite locally to verify code changes:

```bash
python -m pytest --disable-warnings
```

## Legal Disclosure

This tool is built strictly for authorized security auditing and educational research. You must have explicit permission from the target system owner before running any scans. The contributors assume no liability for misuse, unauthorized actions, or damages. See [LEGAL.md](LEGAL.md) for full terms.
