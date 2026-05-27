# VScanX — verification‑driven security analysis framework

VScanX started as “a scanner with modules” and has evolved into an **event‑driven, verification‑centric security analysis pipeline** designed for **low‑noise, reproducible workflows** (authorized testing only).

What makes VScanX different is not “more checks” — it’s:
- **Canonical findings** with stable identity and lifecycle semantics
- **Replay + diff + verify‑only replay** (security state evolution over time)
- **Typed event contracts** (maintainable orchestration and plugins)
- **Verification‑first design** (reduce false positives; increase trust)

---

## Legal / ethics

**Authorized security testing only.** You must have explicit permission to scan any target system.

---

## Install

```bash
python -m pip install -r requirements.txt
python vscanx.py -h
```

---

## Quick usage

### Run a scan (and save state)

Use `--scan-id` if you want replay/diff later:

The developers assume NO liability for misuse of this tool. See [LEGAL.md](LEGAL.md) for complete terms.

## 🎯 Why I Built This

Most beginners rely on tools without understanding how vulnerabilities are detected.

I built VScanX to explore:
- How scanners actually identify vulnerabilities
- The limitations of automated detection
- How real-world edge cases affect scanning accuracy

This project focuses on understanding detection logic, not just using tools.

## 🎯 Features

### What it does today
- **Authenticated scanning**: optional bearer/API-key/login/session support.
- **Web modules**: SQLi (error/boolean/time-based), XSS, headers, dir enum, CVE check.
- **Network**: TCP port scanning with service hints; optional parallel web modules.
- **Structured output**: JSON schema validation, sanitized exports (HTML/JSON/CSV/TXT/PDF).
- **Observability**: JSON logging, metrics artifact, optional debug capture with redaction.
- **Ethical defaults**: legal warning, rate limiting, safe payloads, opt-in parallelism.
- **CI/tests**: ruff + pytest/coverage, fuzz/heuristic tests, schema validation, no-print check in modules.

### Future Planned Features
- Service fingerprinting
- Plugin loader (dynamic module discovery)
- Packaging & distribution (PyPI/installer)

## 🧠 Key Learnings

- Automated scanners cannot replace manual analysis
- Many vulnerabilities require context-aware detection
- False positives and edge cases are major challenges
- Security tools are only as good as the logic behind them

## 🧪 Testing & CI/CD

VScanX includes automated testing and continuous integration:
- Ruff linting (GitHub Actions)
- Pytest with coverage (unit + smoke + fuzz/heuristics)
- CI check to block `print()` in modules
- Local testing: see [TESTING.md](TESTING.md) for complete guide

Run all tests locally:
```bash
python vscanx.py -t "http://example.com" -s web --scan-id run1 --format html,json,csv,txt
```

### Replay (reports only; no scanning)

```bash
python vscanx.py --replay --scan-id run1 --state-dir .vscanx_state --format html,json
```

### Diff two prior scans (security evolution)

```bash
python vscanx.py --diff --scan-id run1 --scan-id2 run2 --state-dir .vscanx_state -o diff_run1_to_run2
```

Produces: `reports/diff_run1_to_run2.diff.json`

### Verify‑only replay (trust upgrade)

This does **not** crawl or run scanners. It only reruns verifier logic using stored `reproduction` contracts.

```bash
python vscanx.py --replay-verify --scan-id run1 --state-dir .vscanx_state -o reverify_run1 --format html,json
```

This writes:
- `.vscanx_state/run1/results_reverify.json`
- `reports/reverify_run1.html` (and other selected formats)

If you need auth context for verification requests, you can pass bearer/api‑key/session flags (same as scan).

---

## Key CLI flags (high value)

- **State & workflows**
  - `--scan-id <id>`: persist results and artifacts for replay/diff
  - `--state-dir <dir>`: persistent state root (default `.vscanx_state`)
  - `--resume`: reuse cached crawl inventory for the same `--scan-id`
  - `--replay`: regenerate reports from saved results
  - `--diff`: diff two saved scans (`--scan-id` → `--scan-id2`)
  - `--replay-verify`: rerun verification only from reproduction contracts

- **Orchestration / stability**
  - `--strict-events`: fail fast on invalid internal event payloads (recommended for CI/dev only)
  - `--parallel-modules`: run web modules in parallel (experimental)
  - `--debug-capture`: capture redacted request/response metadata (diagnostics)

- **Export**
  - `--format html,json,csv,txt` (comma‑separated)
  - `--no-report` to skip report generation

---

## What VScanX does today

### Framework‑core capabilities
- **Canonical finding model** (`finding_id`, timestamps, structured evidence, verification state, enrichment history)
- **Typed event contracts** with optional strict enforcement (`--strict-events`)
- **Capability‑aware orchestration** (auth gating, budgeting via module request cost)
- **Replayability** (saved scan results) + **diffing** + **verify‑only replay**
- **Reliability & observability**
  - Request telemetry (`RequestHandler.get_stats()`)
  - Response body caps + truncation markers
  - Crawler telemetry + skip reasons + deterministic frontier
  - Internal Scan Graph artifact (events, skip reasons, handler stats)

### Modules (examples)
The repo includes web scanners such as:
- Tech stack fingerprinting
- Headers analysis (CSP/HSTS/Permissions‑Policy checks)
- XSS / SQLi detectors
- Directory enumeration (recursive options)
- Open redirect probing (with verification)
- IDOR detection (with verification)
- HPP detection (with verification)
- JS secret analysis
- Subdomain recon (active DNS wordlist)

---

## Architecture docs (for contributors / “another AI”)

Start here:
- `docs/ARCHITECTURE.md` — orchestration lifecycle + strictness principles
- `docs/EVENTS.md` — event types + payload contracts
- `docs/FINDINGS.md` — canonical finding semantics + evidence model
- `docs/MODULES.md` — module capability declarations + orchestration use

---

## State & output directories

- **`reports/`**: generated reports (`.html/.json/.csv/.txt`) and diff outputs (`*.diff.json`)
- **`.vscanx_state/<scan_id>/`**:
  - `crawl.json` (crawler inventory)
  - `results.json` (full canonical scan results)
  - `results_reverify.json` (verify‑only replay output)

---

## Testing

```bash
python -m pytest -q
```

---

## Project direction (important)

VScanX is intentionally **not** trying to be “200 vuln classes”.

The strongest path is:
**verification‑driven recon + reproducible, low‑noise findings + workflow intelligence** (state evolution, replay, diffing, trust scoring).

