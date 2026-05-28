# VScanX: Verification-Driven Security Analysis Framework

VScanX is an event-driven, verification-centric security analysis pipeline designed to deliver low-noise, reproducible security workflows. Unlike traditional security tools that rely on passive signature matching and generate high volumes of false positives, VScanX utilizes deterministic state-replay contracts to validate every vulnerability finding, providing developers and security engineers with high-fidelity, machine-verifiable proof of exploitability.

VScanX is completely open source and supports multi-layered testing across Web applications, Web3 smart contracts, network infrastructure, and Agentic AI applications.

---

## Technical Philosophy

The primary objective of VScanX is to upgrade trust in automated security testing. The architecture operates under three core tenets:

1. **Zero-Trust Findings:** A vulnerability is only reported if the system can generate a safe, repeatable reproduction contract that proves exploitability.
2. **State Evolution Tracking:** Security states change over time. VScanX allows teams to capture, replay, and diff scan states across different deployment cycles.
3. **Strict Orchestration Contracts:** Built on top of a typed event bus, the orchestrator coordinates dynamic discovery, crawlers, and scanning modules safely under custom traffic budgets.

---

## Core Capabilities

### Verification-First Orchestration
Traditional scanners alert on "potential" vulnerabilities based on headers or simple regex matches. VScanX uses active validation. When a module detects a potential vulnerability, it triggers a verifier subprocess. The verifier attempts to trigger the vulnerability using safe payloads and logs the exact HTTP request, response sequence, and mutation vectors as a reproduction contract.

### Security State Diffing & Replay
By tracking scan history via scan identifiers, you can compare security posture over time.
* **Replay:** Regenerate comprehensive reports locally using stored scan results without re-scanning.
* **Verify-Only Replay:** Execute only the lightweight verifier checks against live targets using saved reproduction contracts to verify if past findings are patched.
* **Diffing:** Compare two scans to identify new, resolved, or changed security vulnerabilities between deployments.

### Multi-Threaded Modular Engine
VScanX dynamically schedules compatible modules based on automated target stack fingerprinting and parameter discovery:
* **Web App Auditing:** Boolean, error, and time-based SQL Injection, Reflected Cross-Site Scripting (XSS), IDOR, HTTP Parameter Pollution, Header Analysis, and JS Secret Analysis.
* **Smart Contract Auditing:** Access control validation, recursive reentrancy loop detection, and weak entropy/randomness checkers.
* **Agentic AI Auditing:** Prompt injection fuzzing, sandbox code execution escape probing, state memory poisoning, and data exfiltration checking.

---

## Installation & Setup

Ensure you have Python 3.10+ installed on your local machine.

1. Clone the repository and navigate to the project directory:
   ```bash
   git clone https://github.com/hnikhil-dev/VScanX.git
   cd VScanX
   ```

2. Install the required dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

3. Verify the installation by displaying the help options:
   ```bash
   python vscanx.py --help
   ```

---

## Command Reference & Workflows

### 1. Execute a Live Scan
Perform a standard web-type scan against a target with a customized scan identifier and export reports in multiple formats:
```bash
python vscanx.py -t "http://127.0.0.1:8080/search?q=test" -s web --scan-id run_001 --format html,json,csv,txt --skip-warning
```

### 2. Verify-Only Replay (Lightweight Regression Check)
Rerun only the verifier logic using previously stored reproduction contracts to check if findings are patched. This does not crawl the target or run full active fuzzing:
```bash
python vscanx.py --replay-verify --scan-id run_001 --state-dir .vscanx_state -o verify_report_001 --format html,json
```

### 3. Generate Scan Diffs (Security Evolution)
Compare a baseline scan against a recent scan to identify security state deviations between two separate commits or deployments:
```bash
python vscanx.py --diff --scan-id run_001 --scan-id2 run_002 --state-dir .vscanx_state -o diff_output_report
```

### 4. Direct Replay
Regenerate visual reports from the local state storage without sending any network traffic:
```bash
python vscanx.py --replay --scan-id run_001 --state-dir .vscanx_state --format html,json
```

---

## CLI Argument Reference

### Scan Configuration
* `-t, --target` - Target URL, IP address, or host domain.
* `-s, --scan-type` - Type of scan to perform (`web`, `network`, `mixed`, `web3`, `agentic`). Defaults to `mixed`.
* `--ports` - Port range for network scanning (e.g., `1-1024` or `80,443`).
* `--profile` - Predefined scan configuration profile (`quick`, `normal`, `full`, `stealth`).
* `--only` - Comma-separated list of modules to run exclusively (e.g. `xss,sqli,headers`).
* `--delay` - Delay between outgoing network requests in seconds.

### State & Workflow Management
* `--scan-id` - Custom identifier to correlate local state logs, crawl inventories, and reports.
* `--scan-id2` - Second scan identifier used for `--diff` comparisons.
* `--state-dir` - Directory path for persistent scan state storage (defaults to `.vscanx_state`).
* `--resume` - Reuse cached crawler inventory for the matching `--scan-id`.
* `--replay` - Re-render reports from saved results without performing a new scan.
* `--replay-verify` - Rerun verification checks only using stored reproduction contracts.
* `--diff` - Execute a state comparison between `--scan-id` and `--scan-id2`.

### Authentication Options
* `--login-url` - URL of the application login page or authentication endpoint.
* `--username` - Username for session-based authentication.
* `--password` - Password for session-based authentication.
* `--auth-data` - Custom authentication payload structured as a JSON string.
* `--bearer-token` - HTTP Bearer token string.
* `--api-key` - Static API key value.
* `--api-key-header` - Header key name for the static API key (defaults to `X-API-Key`).
* `--session-file` - File path to load a saved session state from.
* `--save-session` - File path to save authenticated session state to.
* `--success-indicator` - Substring in the response body indicating successful authentication.

### Advanced Controls
* `--elite` - Enable elite automation post-processing layer (vuln chaining, proof of concept generation, and OOB callback handling).
* `--defensive-variants` - Enable defensive URL normalization variant checks (reports inconsistencies only).
* `--oob-base-url` - Base URL for out-of-band callback listeners.
* `--strict-events` - Fail fast on invalid internal event payloads (highly recommended for CI environments).
* `--parallel-modules` - Execute web modules concurrently.
* `--debug-capture` - Capture redacted HTTP request and response metadata.

---

## Directory Architecture

VScanX structures state caching and generated outputs in clean, separate folders:

```
├── .vscanx_state/           # Persistent local state directory
│   └── <scan_id>/
│       ├── crawl.json       # Cached crawler URL inventory
│       ├── results.json     # Complete canonical scan results
│       └── results_reverify.json
├── reports/                 # Document exports folder
│   ├── vscanx_report.html   # High-end interactive HTML report
│   ├── vscanx_report.json   # Validated JSON results
│   ├── vscanx_report.csv    # Spreadsheet layout
│   └── vscanx_report.txt    # Console-friendly plain text summary
├── core/                    # Core orchestration framework
├── modules/                 # Security scanning plugins
└── website/                 # Interactive Next.js documentation dashboard
```

---

## Development & testing

Unit tests, fuzz testing, and heuristics are coordinated using pytest. Run the test suite:
```bash
python -m pytest --disable-warnings
```

---

## Legal & Ethical Disclosure

VScanX is built exclusively for authorized penetration testing, security auditing, and educational research. You must obtain explicit permission from the target system owner before conducting any security scans. The developers and contributors assume no liability for misuse, unauthorized testing, or damage caused by this security framework. For complete terms, please refer to [LEGAL.md](LEGAL.md).
